
WASI_SDK_PATH ?= /home/nskernel/wasi/wasi-sdk-20.0
AOTCC       := /home/nskernel/wasm-micro-runtime/wamr-compiler/build/wamrc
WASMOPT     := /home/nskernel/binaryen/bin/wasm-opt -O4 --enable-bulk-memory

PCD_ROOT := ../../../../

include $(PCD_ROOT)/config.mk
include $(PCD_ROOT)/buildenv.mk

C_Flags += -I../include -nodefaultlibs

all: disc.aot

disc.aot: disc.wasm
	@echo [AOT] AOT Compiling $@
	@$(AOTCC) -sgx --size-level=1 -o $@ $<

disc.wasm: disc.c
	@echo "  CLANG $@"
	@clang -nostdlib $(C_Flags) --target=wasm32 -Wl,--no-entry -Wl,--export=main -Wl,--allow-undefined -Wl,--export=__heap_base -Wl,--export=__data_end disc.c -o disc.wasm
	@echo [OPT] Optimsing $@
	@$(WASMOPT) -o $@ $@
#@/home/nskernel/wasi/wasi-sdk-19.0/bin/clang $(C_Flags) -nostdlib -z stack-size=4194304 -Wl,--initial-memory=16777216 -o disc.wasm disc.c -Wl,--export=main -Wl,--export=__main_argc_argv -Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--no-entry -Wl,--allow-undefined
