#
# Makefile for Update client
#
# List of subdirectories to build
TEST_FOLDER := ./TESTS

# Define compiler toolchain with CC or PLATFORM variables
# Example (GCC toolchains, default $CC and $AR are used)
# make
#
# OR (Cross-compile GCC toolchain)
# make PLATFORM=arm-linux-gnueabi-
#
# OR (ArmCC/Keil)
# make CC=ArmCC AR=ArmAR
#
# OR (IAR-ARM)
# make CC=iccarm

LIB = libupdateclient.a

# List of unit test directories for libraries
UNITTESTS := $(sort $(dir $(wildcard $(TEST_FOLDER)*/unittest/*)))

# If configuration is not specified, use linux
ifeq (,$(CONFIG))
CONFIG := linux
endif

FLAGS += TARGET_LIKE_LINUX

ifeq ($(DEBUG),1)
override CFLAGS += -DHAVE_DEBUG
endif

COVERAGEFILE := ./lcov/coverage.info

#
# Define compiler toolchain
#
include ../../libService/toolchain_rules.mk

$(eval $(call generate_rules,$(LIB),$(SRCS)))

# Extend default clean rule
clean: clean-extra

$(CLEANDIRS):
	@make -C $(@:clean-%=%) clean

clean-extra: $(CLEANDIRS)
