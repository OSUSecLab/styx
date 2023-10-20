
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

# Crypto configurations

C_Files += crypto/crypto.c
ifdef CONFIG_CRYPTO_PLAIN
ifeq ($(CONFIG_CRYPTO_PLAIN), y)
C_Flags += -DPCD_CONFIG_CRYPTO_PLAIN
C_Files += $(wildcard crypto/plain/*.c)
endif
endif

ifdef CONFIG_CRYPTO_AES_GCM
ifeq ($(CONFIG_CRYPTO_AES_GCM), y)
C_Flags += -DPCD_CONFIG_CRYPTO_AES_GCM
C_Files += $(wildcard crypto/aes_gcm/*.c)
endif
endif


# Policy configurations

C_Files += policy/policy.c
ifdef CONFIG_POLICY_SIMPLE
ifeq ($(CONFIG_POLICY_SIMPLE), y)
C_Flags += -DPCD_CONFIG_POLICY_SIMPLE
C_Files += $(wildcard policy/simple/*.c)
endif
endif


# Roles

ifdef CONFIG_ROLE_TRANSFORMER
ifeq ($(CONFIG_ROLE_TRANSFORMER), y)
CONFIG_SECRET_REQUESTER := y
CONFIG_DATA_PACKER := y
CONFIG_DATA_UNPACKER := y
C_Files += $(wildcard framework/transformer/*.c)
endif
endif

ifdef CONFIG_ROLE_CONSUMER
ifeq ($(CONFIG_ROLE_CONSUMER), y)
CONFIG_SECRET_REQUESTER := y
CONFIG_DATA_UNPACKER := y
C_Files += $(wildcard framework/consumer/*.c)
endif
endif

ifdef CONFIG_ROLE_PRODUCER
ifeq ($(CONFIG_ROLE_PRODUCER), y)
CONFIG_DATA_PACKER := y
C_Files += $(wildcard framework/producer/*.c)
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

# Modules

C_Files += framework/common/log.c 
Cpp_Files += framework/common/secret.cpp

ifdef CONFIG_SECRET_REQUESTER
ifeq ($(CONFIG_SECRET_REQUESTER), y)
C_Flags += -DPCD_CONFIG_SECRET_REQUESTER
endif
endif

ifdef CONFIG_DATA_PACKER
ifeq ($(CONFIG_DATA_PACKER), y)
C_Files += framework/common/data_packer.c
endif
endif

ifdef CONFIG_DATA_UNPACKER
ifeq ($(CONFIG_DATA_UNPACKER), y)
C_Files += framework/common/data_unpacker.c
endif
endif
