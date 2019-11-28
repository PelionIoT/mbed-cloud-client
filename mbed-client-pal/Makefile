## ----------------------------------------------------------- ##
## Don't touch the next line unless you know what you're doing.##
## ----------------------------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilevars.mk

# Name of the module
LOCAL_NAME := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal

# list all modules APIs that are necessary to compile this module
LOCAL_API_DEPENDS := \
                    platform/service/net/lwip \
                    ${API_PLATFORM_DEPENDS} \

LOCAL_ADD_INCLUDE := \
                    ${LOCAL_NAME}/Source \
                    ${LOCAL_NAME}/Source/PAL-Impl \
                    ${LOCAL_NAME}/Source/PAL-Impl/Services-API \
                    ${LOCAL_NAME}/Source/Port/Platform-API \
                    ${LOCAL_NAME}/Configs/pal_config \
                    ${LOCAL_NAME}/Configs/pal_config/SXOS \

LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-client-platform/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/nanostack-libservice/mbed-client-libservice \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/sal-stack-nanostack-eventloop/nanostack-event-loop \
                    platform/service/net/mbedtls/src/mbedtls/include/mbedtls \

# FCC (==ESFS&SOTP)
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/mbed-client-esfs/source/include \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/storage/storage \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/storage/source/include \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/key-config-manager/key-config-manager \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/crypto-service/crypto-service \

# and tests dependencies
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/source/platform/include \


# direct PAL to its OS specific config file
LOCAL_EXPORT_FLAG += "'PAL_USER_DEFINED_CONFIGURATION=\"SXOS/sxos_sotp.h\"'"

LOCAL_EXPORT_FLAG += __SXOS__


# Compile the sub-modules, except when the "service" must be used as a library.
# list all the modules that need to be compiled prior to using this module


# Generate the revision (version) file automatically during the make process.
AUTO_GEN_REVISION_HEADER := no

# This is a top-level module
IS_TOP_LEVEL := no

# code is not in one "src/" directory as SDK expects by default
USE_DIFFERENT_SOURCE_LAYOUT := yes
USE_DIFFERENT_SOURCE_LAYOUT_ARM := yes

# Generates the CoolWatcher headers automatically.
AUTO_XMD2H ?= no

# the platform agnostic service layer
C_SRC += ${wildcard Source/PAL-Impl/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Crypto/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/DRBG/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Networking/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/ROT/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/RTOS/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Storage/FileSystem/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Storage/Flash/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Time/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/TLS/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Update/*.c}
C_SRC += ${wildcard Source/PAL-Impl/Modules/Entropy/*.c}


# library specific
C_SRC += ${wildcard Source/Port/Reference-Impl/Lib_Specific/mbedTLS/Crypto/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Lib_Specific/mbedTLS/TLS/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Lib_Specific/mbedTLS/DRBG/*.c}

# platform specific code
C_SRC += ${wildcard Source/Port/Reference-Impl/OS_Specific/SXOS/RTOS/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/OS_Specific/SXOS/Networking/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/OS_Specific/SXOS/Storage/FileSystem/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/Time/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/DRBG/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/DRBG/SOTP/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/Entropy/SOTP/*.c}

# flash emulation layer
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/Storage/Flash/*.c}

C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/ROT/SOTP/*.c}
C_SRC += ${wildcard Source/Port/Reference-Impl/Generic/ROT/External/*.c}

# tests are in separate palTests library




## ------------------------------------- ##
##  Do Not touch below this line         ##
## ------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilerules.mk
