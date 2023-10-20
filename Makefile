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

include config.mk
include buildenv.mk

# Select platform

include platforms/$(CONFIG_PLATFORM)/platform_buildenv.mk

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

# Build enclave lib

$(Trusted_Lib_Name): $(C_Objs) $(Cpp_Objs)
	@echo "  AR    $@"
	@$(AR) rcs $@ $^


$(C_Objs): %.o: %.c
	@echo "  CC    $@"
	@$(CC) $(C_Flags) -c $< -o $@


$(Cpp_Objs): %.o: %.cpp
	@echo "  CXX   $@"
	@$(CXX) $(Cpp_Flags) -c $< -o $@

# Build untrusted lib


$(Untrusted_Lib_Name): $(Untrusted_C_Objs) $(Untrusted_Cpp_Objs)
	@echo "  AR    $@"
	@$(AR) rcs $@ $^


$(Untrusted_C_Objs): %.o: %.c
	@echo "  UCC   $@"
	@$(CC) $(Untrusted_C_Flags) -c $< -o $@


$(Untrusted_Cpp_Objs): %.o: %.cpp
	@echo "  CXX   $@"
	@$(CXX) $(Untrusted_Cpp_Flags) -c $< -o $@
