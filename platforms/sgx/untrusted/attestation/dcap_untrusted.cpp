#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "sgx_dcap_ql_wrapper.h"
#include "sgx_quote_3.h"

extern "C" {

#include "log.h" // TODO: untrusted_log.h

}

/**
 * @param qe_target_info - [out]ECDSA qe target info
 */
extern "C" uint32_t ocall_ecdsa_get_qe_target_info(sgx_target_info_t* qe_target_info){
	uint32_t ret = 0;
	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	sgx_target_info_t qe3_target_info;

	// There 2 modes on Linux: one is in-proc mode, the QE3 and PCE are loaded within the user's process.
	// the other is out-of-proc mode, the QE3 and PCE are managed by a daemon. If you want to use in-proc
	// mode which is the default mode, you only need to install libsgx-dcap-ql. If you want to use the
	// out-of-proc mode, you need to install libsgx-quote-ex as well. This sample is built to demo both 2
	// modes, so you need to install libsgx-quote-ex to enable the out-of-proc mode.
        // Following functions are valid in Linux in-proc mode only.
        //pcd_log("sgx_qe_set_enclave_load_policy is valid in in-proc mode only and it is optional: the default enclave load policy is persistent: \n");
        //pcd_log("set the enclave load policy as persistent:");
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
            pcd_log_error("Error in set enclave load policy: 0x%04x\n", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
        //pcd_log("succeed!\n");

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so")) {
                pcd_log_error("Error in set PCE/QE3 directory.\n");
                ret = -1;
                goto CLEANUP;
            }
        }

        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
        if (SGX_QL_SUCCESS != qe3_ret) {
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
            if(SGX_QL_SUCCESS != qe3_ret) {
                // Ignore the error, because user may want to get cert type=3 quote
                pcd_log_warning("Warning: Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.\n");
            }
        }

    //pcd_log("\nStep1: Call sgx_qe_get_target_info:");
    qe3_ret = sgx_qe_get_target_info(&qe3_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        pcd_log_error("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
                ret = -1;
        goto CLEANUP;
    }
    //pcd_log("succeed!");

	memcpy(qe_target_info, &qe3_target_info, sizeof(qe3_target_info));

	CLEANUP:
    return ret;
}

/**
 * @param app_report [in] sgx_report_t* app_report
 * @param quote_buffer - [out]ECDSA quote buffer
 * @param quote_size - [out]ECDSA quote buffer size
 */
extern "C" uint32_t ocall_ecdsa_quote_generation(uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote_buffer){
	uint32_t ret = 0;
	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint8_t *p_quote_buffer = NULL;

    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    //pcd_log("\nStep2: Call create_app_report:");
    

    //pcd_log("succeed!");
    //pcd_log("\nStep3: Call sgx_qe_get_quote_size:");
    qe3_ret = sgx_qe_get_quote_size(quote_size);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        pcd_log_error("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }
	//pcd_log("succeed!");
    p_quote_buffer = (uint8_t *)malloc(*quote_size);
    if (NULL == p_quote_buffer)
    {
        pcd_log("Couldn't allocate quote_buffer\n");
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, *quote_size);

    // Get the Quote
    //pcd_log("\nStep4: Call sgx_qe_get_quote:");
    qe3_ret = sgx_qe_get_quote(app_report,
                               *quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret)
    {
        pcd_log_error("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        goto CLEANUP;
    }
    //pcd_log("succeed!");

	memcpy(quote_buffer, p_quote_buffer, *quote_size);
    p_quote = (sgx_quote3_t *)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t *)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    //pcd_log("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);
	
	CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
}


#include "sgx_dcap_quoteverify.h"

/**
 * @param quote_buffer - [in]ECDSA quote buffer
 * @param quote_size - [in]ECDSA quote buffer size
 */
extern "C" uint32_t ocall_ecdsa_quote_verification(uint8_t* quote_buffer, uint32_t quote_size)
{
    uint32_t ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;

    //pcd_log("size of quote will be verified : %ld\n", quote_size);
    // Untrusted quote verification
    // call DCAP quote verify library to get supplemental data size
    //
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t))
    {
        //pcd_log("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
        p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    }
    else
    {
        if (dcap_ret != SGX_QL_SUCCESS)
            pcd_log_error("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);

        if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t))
            pcd_log_warning("\tWarning: sgx_qv_get_quote_supplemental_data_size returned size is not same with header definition in SGX SDK, please make sure you are using same version of SGX SDK and DCAP QVL.\n");

        supplemental_data_size = 0;
    }

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    dcap_ret = sgx_qv_verify_quote(
        (uint8_t*)quote_buffer, quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret == SGX_QL_SUCCESS)
    {
        //pcd_log("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else
    {
        pcd_log_error("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
    }

    // check verification result
    //
    switch (quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        // check verification collateral expiration status
        // this value should be considered in your own attestation/verification policy
        //
        if (collateral_expiration_status == 0)
        {
            //pcd_log("\tInfo: App: Verification completed successfully.\n");
            ret = 0;
        }
        else
        {
            pcd_log_warning("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");
            ret = 1;
        }
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        //pcd_log_warning("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        pcd_log_error("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
        ret = -1;
        break;
    }

    // check supplemental data if necessary
    //
    if (p_supplemental_data != NULL && supplemental_data_size > 0)
    {
        sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)p_supplemental_data;

        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
       //pcd_log("\tInfo: Supplemental data version: %d\n", p->version);
    }

    return ret;
}
