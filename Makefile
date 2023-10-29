include config.mk
include buildenv.mk

Trusted_Lib_Name := libtpcd.a
Untrusted_Lib_Name := libupcd.a

C_Objs := $(sort $(C_Files:.c=.o))
Cpp_Objs := $(sort $(Cpp_Files:.cpp=.o))
Untrusted_C_Objs := $(sort $(Untrusted_C_Files:.c=.o))
Untrusted_Cpp_Objs := $(sort $(Untrusted_Cpp_Files:.cpp=.o))

# All

.PHONY: all clean

all: $(Trusted_Lib_Name) $(Untrusted_Lib_Name)

clean:
	rm -f $(Trusted_Lib_Name) $(Untrusted_Lib_Name)
	rm -f $(C_Objs)
	rm -f $(Cpp_Objs)
	rm -f $(Untrusted_C_Objs)
	rm -f $(Untrusted_Cpp_Objs)

# Build runtime lib

ifdef CONFIG_RUNTIME_WAMR
ifeq ($(CONFIG_RUNTIME_WAMR), y)
$(Untrusted_Runtime_Libs) $(Trusted_Runtime_Libs):
	@echo "  MAKE  runtime/wamr"
	@make -C runtime/wamr
endif
endif

# Build enclave lib

$(Trusted_Lib_Name): $(C_Objs) $(Cpp_Objs) $(Trusted_Runtime_Libs)
	@echo "  AR    $@"
ifneq ($(Trusted_Runtime_Libs), )
	@cp $(Trusted_Runtime_Libs) $@
endif
	@$(AR) rcs $@ $(C_Objs) $(Cpp_Objs)


$(C_Objs): %.o: %.c
	@echo "  CC    $@"
	@$(CC) $(C_Flags) -c $< -o $@


$(Cpp_Objs): %.o: %.cpp
	@echo "  CXX   $@"
	@$(CXX) $(Cpp_Flags) -c $< -o $@

# Build untrusted lib

$(Untrusted_Lib_Name): $(Untrusted_C_Objs) $(Untrusted_Cpp_Objs) $(Untrusted_Runtime_Libs)
	@echo "  AR    $@"
ifneq ($(Untrusted_Runtime_Libs), )
	@cp $(Untrusted_Runtime_Libs) $@
endif
	@$(AR) rcs $@ $(Untrusted_C_Objs) $(Untrusted_Cpp_Objs)


$(Untrusted_C_Objs): %.o: %.c
	@echo "  UCC   $@"
	@$(CC) $(Untrusted_C_Flags) -c $< -o $@


$(Untrusted_Cpp_Objs): %.o: %.cpp
	@echo "  CXX   $@"
	@$(CXX) $(Untrusted_Cpp_Flags) -c $< -o $@
