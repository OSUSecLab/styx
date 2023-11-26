SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

include $(SGX_SDK)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
SGX_COMMON_FLAGS := -m32
SGX_LIBRARY_PATH := $(SGX_SDK)/lib
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

ifneq ($(SGX_MODE), HW)
Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_tservice_sim
else
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Include_Paths += -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx


PLATFORM_DIR := $(ROOT_DIR)/platforms/sgx

Include_Paths += -I$(PLATFORM_DIR)/include

Untrusted_Include_Paths += -I$(PLATFORM_DIR)/untrusted/include -I$(SGX_SDK)/include

C_Files += $(PLATFORM_DIR)/log_backend.c

Untrusted_C_Files += $(PLATFORM_DIR)/untrusted/log.c

# Crypto configurations

ifdef CONFIG_CRYPTO_AES_GCM
ifeq ($(CONFIG_CRYPTO_AES_GCM), y)
C_Flags += -DPCD_CONFIG_CRYPTO_AES_GCM
C_Files += $(wildcard $(PLATFORM_DIR)/crypto/aes_gcm/*.c)
endif
endif

C_Files += $(PLATFORM_DIR)/crypto/sha256.c

# Modules

ifdef CONFIG_SECRET_REQUESTER
ifeq ($(CONFIG_SECRET_REQUESTER), y)
CONFIG_SGX_ATTESTATION_CHALLENGER = y
Cpp_Files += $(PLATFORM_DIR)/secret_provisioning/secret_requester.cpp
endif
endif

ifdef CONFIG_SECRET_OWNER
ifeq ($(CONFIG_SECRET_OWNER), y)
CONFIG_SGX_ATTESTATION_CHALLENGER = y
Cpp_Files += $(PLATFORM_DIR)/secret_provisioning/secret_owner.cpp
endif
endif

ifdef CONFIG_SECRET_PROVIDER
ifeq ($(CONFIG_SECRET_PROVIDER), y)
CONFIG_SGX_ATTESTATION_PROVER = y
Cpp_Files += $(PLATFORM_DIR)/secret_provisioning/secret_provider.cpp
endif
endif

# Attestation

ifdef CONFIG_SGX_ATTESTATION_CHALLENGER
ifeq ($(CONFIG_SGX_ATTESTATION_CHALLENGER), y)
C_Flags += -DPCD_CONFIG_ATTESTATION_CHALLENGER
CONFIG_SGX_ATTESTATION = y
Cpp_Files += $(PLATFORM_DIR)/attestation/challenger/challenger.cpp
Untrusted_Cpp_Files += $(wildcard $(PLATFORM_DIR)/untrusted/attestation/challenger/*.cpp)
endif
endif

ifdef CONFIG_SGX_ATTESTATION_PROVER
ifeq ($(CONFIG_SGX_ATTESTATION_PROVER), y)
CONFIG_SGX_ATTESTATION = y
Cpp_Files += $(PLATFORM_DIR)/attestation/prover/prover.cpp
Untrusted_Cpp_Files += $(wildcard $(PLATFORM_DIR)/untrusted/attestation/prover/*.cpp)
endif
endif

ifdef CONFIG_SGX_ATTESTATION
ifeq ($(CONFIG_SGX_ATTESTATION), y)
CONFIG_SGX_ATTESTATION = y
Include_Paths += -I$(PLATFORM_DIR)/attestation/include
Cpp_Files += $(wildcard $(PLATFORM_DIR)/attestation/*.cpp)
Untrusted_Cpp_Files += $(wildcard $(PLATFORM_DIR)/untrusted/attestation/*.cpp)
endif
endif

ifdef CONFIG_RUNTIME_WAMR
ifeq ($(CONFIG_RUNTIME_WAMR), y)
Untrusted_C_Files += $(PLATFORM_DIR)/untrusted/read_file_outside.c
endif
endif

# Flags

C_Flags += -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS)

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
C_Flags += -fstack-protector
else
C_Flags += -fstack-protector-strong
endif

