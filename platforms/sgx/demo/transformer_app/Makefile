
WASI_SDK_PATH ?= /home/nskernel/wasi/wasi-sdk-19.0


PCD_ROOT := ../../../../

include $(PCD_ROOT)/config.mk
include $(PCD_ROOT)/buildenv.mk

C_Flags += -I../include -nodefaultlibs -Wl,-lc

all: app.wasm

app.wasm: app.c
	@echo "  CLANG $@"
	@$(WASI_SDK_PATH)/bin/clang -I$(WASI_SDK_PATH)/share/wasi-sysroot/include/ $(C_Flags) --sysroot=$(WASI_SDK_PATH)/share/wasi-sysroot/ -Wl,--allow-undefined -Wl,--export=main app.c -o app.wasm
	@echo "  HASH  $@"
	@sha256sum app.wasm | cut -d " " -f 1 | xxd -r -p > app.hash
	@cp app.hash ../
