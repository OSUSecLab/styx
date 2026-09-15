# Styx Artefacts


## How to build the `libonnx` demo with SGX and WAMR

While the Styx framework can be extended to support more TEEs (or without any TEE) and runtimes, we provide only SGX and WAMR support out of the box. Here is how to build it and how to run it. Suppose you are at `~`

### Step 0. Prepare the environment

Build [Intel SGX SDK](https://github.com/intel/linux-sgx) and install the SDK, PSW. The reference commit for this project is `f47d0e5a01bf68cebefce4418cf364777e76d503` (Version 2.21). Prepare your system for DCAP following [this guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html).

Download a [WASI SDK](https://github.com/WebAssembly/wasi-sdk) to build WASM apps. The reference version iw [WASI SDK 20](https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-20). Note that you don't have to complile it. Just download from the release page.

### Step 1. Clone the repo and pull submodules

```
git clone https://github.com/OSUSecLab/policy-carrying-data.git
git submodule update --init
```

### Step 2. Build the key management system (Delegator)

Change the `config.mk`'s line 20 to `y`, line 16-19 to `n`. Then,
```
make
```
This will build the delegator library. Now head to the platform demo folder to build the app.
```
cd platform/sgx/demo/delegator
make
```

### Step 3. Build the producer-owner combo app

Change the `config.mk`'s line 18-19 to `y`, line 16-17 and 20 to `n`. Then,
```
make
```
This will build the producer-owner combo library. Now head to the platform demo folder to build the app.
```
cd platform/sgx/demo/producer_owner
make
```

### Step 4. Build the transformer middleware

Change the `config.mk`'s line 16 to `y`, line 17-20 to `n`. Then,
```
make
```
This will build the transformer library. Note that the runtime will also be built to sandbox the transformer app. Now head to the platform demo folder to build the app.
```
cd platform/sgx/demo/transformer_middleware
make
```

### Step 5. Build the DISC (policy engine)

Note that we used to refer the policy language (and its engine) with the name 'DISC'. This is a legacy name.

Keep the `config.mk` as the one you use for the transformer middleware,
```
cd platform/sgx/demo/transformer_disc
WASI_SDK_PATH=<your WASI SDK path> make
```

### Step 6. Build the `libonnx` and the `hello` demo

Keep the `config.mk` as the one you use for the transformer middleware,
```
cd platform/sgx/demo/libonnx
WASI_SDK_PATH=<your WASI SDK path> make
```

### Step 7. Run the demo

We provided 3 demo owner UUIDs and a demo DISC UUID under the demo folder. You can also generate your own. Prepare 3 terminals. In termial 1,
```
cd platform/sgx/demo/delegator
./delegator /tmp/UNIX0.domain
```
This will setup a delegator server at address /tmp/UNIX0.domain. Do not quit the delegator.

In terminal 2,
```
cd platform/sgx/demo/producer_owner
./producer_owner ../owner_b.uuid ./app.hash
```
This will make the owner of the generated data to be owner b and requires the app with a hash matches app.hash to access the data. You will see it asks you for commands. Do the following:
```
Enter command: a ../libonnx-pcd/examples/hello/mnist.onnx 1 ../mnist.onnx
```
The output will be
```
INFO: output_data's max size is set to 34650
INFO: input_data_size = 26454
[?] dataset: DEBUG: payload[00]: 08 03 12 04 43 4E 54 4B
[?] dataset: DEBUG: payload[01]: 1A 05 32 2E 35 2E 31 22
[?] dataset: DEBUG: payload[02]: 07 61 69 2E 63 6E 74 6B
INFO: 2e3d1441-3f74-ee11-b85a-8791d7dec2d2 secret found
INFO: ecall_pack_data returned 0
```
Then
```
Enter command: a ../libonnx-pcd/examples/hello/input_3 1 ../input_3
```
You will see a similar output. This will generate two data: `mnist.onnx` is the a model for the common `mnist` handwriting number recogonisation. `input_3` is, while the name is bad, a bitmap representation of a number 2. They two pieces of data are packed into policy-carrying data and are encrypted. Now enter command `p` to push owner b's key to the delegator then `q` to exit.
```
Enter command: p
```
The output will be
```
        Warning: App: Verification completed with Non-terminal result: a002

INFO: Sending EE113F742E3D1441's secret
Enter command: q
Exiting...
Done
```

In terminal 3, 
```
cd platform/sgx/demo/transformer_middleware
./transformer
```
This will launch the transformer. You will be prompted to enter how many DISCs you want to load and then the path and UUID of each DISC. We just enter 1 and give the path of the DISC module we just compiled
```
Enter DISC count> 1
Enter DISC module path> ../transformer_disc/disc.wasm
Enter custodian DISC UUID path>  ../demo_disc.uuid
```
Then you will be asked for the app's path. We will use the `hello` from `libonnx`. We pretend to be owner a, just someone different from owner b, to see the key-fetching from delegator
```
Enter app module path> ../libonnx-pcd/examples/hello/hello
Enter custodian ID UUID path> ../owner_a.uuid
```
You will see a bunch of output
```
[+] Middleware: INFO: App loaded
INFO: secret size is 16
INFO: b8bcb13f-3f74-ee11-9147-e329dfb08d79 secret registered
[+] Middleware: INFO: Secret registered
DEBUG: dir_allow: /home/.../pcd/platforms/sgx/demo/
Enter owner ID path: INFO: buf_size = 16
[+] Owner ID setb8bcb13f-3f74-ee11-9147-e329dfb08d79
Enter model path: INFO: buf_size = 26679
Enter input path:
INFO: buf_size = 3361
[+] Dataset 0 ready
```
Now, enter the model's path. Note that we need the PAD encrypted one.
```
../mnist.onnx
```
You will see
```
INFO: req_msg type is 0
INFO: req_msg type is 2
        Warning: App: Verification completed with Non-terminal result: a002

INFO: req_msg type is 4
INFO: req_msg type is 6
INFO: secret size is 16
INFO: 2e3d1441-3f74-ee11-b85a-8791d7dec2d2 secret registered
INFO: 2e3d1441-3f74-ee11-b85a-8791d7dec2d2 secret found
INFO: pcd_dataset_add_data: fetched secret
algo is 1
INFO: dataset 0's policy is 6ed8da91-2474-ee11-b962-0242ac120002
[+] hello: INFO: Added model to dataset
```
We indeed fetched the key from the delegator and the model has been added to the dataset. Now we add the input
```
../input_3
```
You will see
```
INFO: req_msg type is 0
INFO: req_msg type is 2
        Warning: App: Verification completed with Non-terminal result: a002

INFO: req_msg type is 4
INFO: req_msg type is 6
INFO: secret size is 16
INFO: 2e3d1441-3f74-ee11-b85a-8791d7dec2d2 secret registered
INFO: 2e3d1441-3f74-ee11-b85a-8791d7dec2d2 secret found
INFO: pcd_dataset_add_data: fetched secret
algo is 1
[+] hello: INFO: Added input to dataset
DEBUG: Entering pcd_dataset_check_policy. dataset_index = 0
[05:51:54:412 - 0]: warning: failed to link import function (env, __stack_chk_fail)
INFO: eval function returned 0
INFO: Policy check passed
[+] hello: INFO: Policy passed
INFO: Ground truth matches
[+] hello: INFO: model size is 26454
                 First 16 bytes are
                 08 03 12 04 43 4E 54 4B
                 1A 05 32 2E 35 2E 31 22
                 Last 16 bytes are
                 12 08 0A 02 08 01 0A 02
                 08 0A 42 04 0A 00 10 08
[+] hello: INFO: input size is 3136
Plus214_Output_0: float32[1 x 10] =
[[975.67, -618.724, 6574.57, 668.028, -917.272, -1671.64, -1952.76, -61.5493, -777.176, -1439.53,]]
INFO: main function returned 0
INFO: pcd_app_run: main returned 0
[+] Middleware: INFO: App finished
[+] Middleware: INFO: App unloaded
Exiting...
Done
```
After adding the input, the program will automatically check the policy over the dataset, perform the model loading and the predicting. We can see that in the result vector, the third one has the largest value (6574.57), since the vector starts from 0, we can say that the model predicted correctly.
