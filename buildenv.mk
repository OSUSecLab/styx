# -----------------------------------------------------------------------------
# Function : parent-dir
# Arguments: 1: path
# Returns  : Parent dir or path of $1, with final separator removed.
# -----------------------------------------------------------------------------
parent-dir = $(patsubst %/,%,$(dir $(1:%/=%)))

# -----------------------------------------------------------------------------
# Macro    : my-dir
# Returns  : the directory of the current Makefile
# Usage    : $(my-dir)
# -----------------------------------------------------------------------------
my-dir = $(realpath $(call parent-dir,$(lastword $(MAKEFILE_LIST))))


ROOT_DIR              := $(call my-dir)

C_Flags := 
Cpp_Flags := 

C_Files := 
Cpp_Files := 


Untrusted_C_Flags := 
Untrusted_Cpp_Flags := 

Untrusted_C_Files :=
Untrusted_Cpp_Files :=

Include_Paths := -I$(ROOT_DIR)/include 
Untrusted_Include_Paths := 

Runtime_Name :=
Trusted_Runtime_Libs := 
Untrusted_Runtime_Libs :=

# Crypto configurations

C_Files += $(ROOT_DIR)/crypto/crypto.c
ifdef CONFIG_CRYPTO_PLAIN
ifeq ($(CONFIG_CRYPTO_PLAIN), y)
C_Flags += -DPCD_CONFIG_CRYPTO_PLAIN
C_Files += $(wildcard $(ROOT_DIR)/crypto/plain/*.c)
endif
endif

ifdef CONFIG_CRYPTO_AES_GCM
ifeq ($(CONFIG_CRYPTO_AES_GCM), y)
C_Flags += -DPCD_CONFIG_CRYPTO_AES_GCM
C_Files += $(wildcard $(ROOT_DIR)/crypto/aes_gcm/*.c)
endif
endif

C_Files += $(ROOT_DIR)/crypto/sha256.c

# Roles

ifdef CONFIG_ROLE_TRANSFORMER
ifeq ($(CONFIG_ROLE_TRANSFORMER), y)
CONFIG_SECRET_REQUESTER := y
CONFIG_DATA_PACKER := y
CONFIG_DATA_UNPACKER := y
CONFIG_POLICY_ENGINE := y
CONFIG_DATASET := y
CONFIG_DATA_GENERATOR := y
CONFIG_NEED_RUNTIME := y
endif
endif

ifdef CONFIG_ROLE_CONSUMER
ifeq ($(CONFIG_ROLE_CONSUMER), y)
CONFIG_SECRET_REQUESTER := y
CONFIG_DATA_UNPACKER := y
CONFIG_POLICY_ENGINE := y
CONFIG_DATASET := y
CONFIG_NEED_RUNTIME := y
endif
endif

ifdef CONFIG_ROLE_PRODUCER
ifeq ($(CONFIG_ROLE_PRODUCER), y)
CONFIG_DATA_PACKER := y
CONFIG_DATA_GENERATOR := y
endif
endif

ifdef CONFIG_ROLE_OWNER
ifeq ($(CONFIG_ROLE_OWNER), y)
CONFIG_SECRET_OWNER := y
endif
endif

ifdef CONFIG_ROLE_DELEGATOR
ifeq ($(CONFIG_ROLE_DELEGATOR), y)
CONFIG_SECRET_PROVIDER := y
endif
endif

# Runtimes

ifdef CONFIG_NEED_RUNTIME
ifeq ($(CONFIG_NEED_RUNTIME), y)
C_Files += $(ROOT_DIR)/framework/app.c

ifdef CONFIG_RUNTIME_WAMR
ifeq ($(CONFIG_RUNTIME_WAMR), y)
C_Flags += -DPCD_CONFIG_RUNTIME_WAMR -I$(ROOT_DIR)/runtime/wamr/wasm-micro-runtime/core/iwasm/include -I$(ROOT_DIR)/runtime/wamr/wasm-micro-runtime/core/iwasm/interpreter -I$(ROOT_DIR)/runtime/wamr/wasm-micro-runtime/core/shared/utils -I$(ROOT_DIR)/runtime/wamr/wasm-micro-runtime/core/shared/platform/linux-sgx
C_Files += $(ROOT_DIR)/runtime/wamr/wamr-binding.c
Runtime_Name := wamr
Trusted_Runtime_Libs := $(ROOT_DIR)/runtime/wamr/build/libvmlib.a
Untrusted_Runtime_Libs := $(ROOT_DIR)/runtime/wamr/build/libvmlib_untrusted.a
endif
endif
endif
endif

# Policy configurations

ifdef CONFIG_POLICY_ENGINE
C_Files += $(ROOT_DIR)/policy/policy.c $(ROOT_DIR)/policy/policy_engine_helpers.c
C_Flags += -DPCD_CONFIG_POLICY_ENGINE
endif

# Modules

C_Files += $(ROOT_DIR)/framework/log.c 
Cpp_Files += $(ROOT_DIR)/framework/secret.cpp

ifdef CONFIG_SECRET_REQUESTER
ifeq ($(CONFIG_SECRET_REQUESTER), y)
C_Flags += -DPCD_CONFIG_SECRET_REQUESTER
endif
endif

ifdef CONFIG_DATA_PACKER
ifeq ($(CONFIG_DATA_PACKER), y)
C_Files += $(ROOT_DIR)/framework/data_packer.c
C_Flags += -DPCD_CONFIG_DATA_PACKER
endif
endif

ifdef CONFIG_DATA_GENERATOR
ifeq ($(CONFIG_DATA_GENERATOR), y)
C_Files += $(ROOT_DIR)/framework/data_generator.c
C_Flags += -DPCD_CONFIG_DATA_GENERATOR
endif
endif

ifdef CONFIG_DATA_UNPACKER
ifeq ($(CONFIG_DATA_UNPACKER), y)
C_Files += $(ROOT_DIR)/framework/data_unpacker.c
C_Flags += -DPCD_CONFIG_DATA_UNPACKER
endif
endif

ifdef CONFIG_DATASET
ifeq ($(CONFIG_DATASET), y)
C_Files += $(ROOT_DIR)/framework/dataset.c
C_Flags += -DPCD_CONFIG_DATASET
endif
endif

# Select platform

include $(ROOT_DIR)/platforms/$(CONFIG_PLATFORM)/platform_buildenv.mk


C_Flags += $(Include_Paths)
Untrusted_C_Flags += $(Untrusted_Include_Paths)


Cpp_Flags += $(C_Flags) -nostdinc++

Untrusted_Cpp_Flags += $(Untrusted_C_Flags)