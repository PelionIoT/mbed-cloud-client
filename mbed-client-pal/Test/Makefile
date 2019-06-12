## ----------------------------------------------------------- ##
## Don't touch the next line unless you know what you're doing.##
## ----------------------------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilevars.mk

# Name of the module
LOCAL_NAME := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Test

PAL_BASE := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal

# list all modules APIs that are necessary to compile this module
LOCAL_API_DEPENDS := \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Test/Unity \
                    ${API_PLATFORM_DEPENDS} \

LOCAL_ADD_INCLUDE := \
                    ${PAL_BASE}/Source \
                    ${PAL_BASE}/Source/PAL-Impl \
                    ${PAL_BASE}/Source/PAL-Impl/Services-API \
                    ${PAL_BASE}/Source/Port/Platform-API \
                    ${PAL_BASE}/Configs/pal_config \
                    ${PAL_BASE}/Configs/pal_config/SXOS \

LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-client-platform/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/nanostack-libservice/mbed-client-libservice \
                    platform/service/net/mbedtls/src/mbedtls/include/mbedtls \

# FCC (==ESFS&SOTP)
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/mbed-client-esfs/source/include \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/storage/storage \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/storage/source/include \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/key-config-manager/key-config-manager \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client/crypto-service/crypto-service \

# test related includes
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/PAL_Modules \
                    ${LOCAL_NAME}/Unity \
                    ${LOCAL_NAME}/Unity/src \
                    ${LOCAL_NAME}/Unity/extras/fixture/src \

# and tests dependencies
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/source/platform/include \


# direct PAL to its OS specific config file
LOCAL_EXPORT_FLAG += "'PAL_USER_DEFINED_CONFIGURATION=\"SXOS/sxos_sotp.h\"'"



# Compile the sub-modules, except when the "service" must be used as a library.
# list all the modules that need to be compiled prior to using this module

LOCAL_MODULE_DEPENDS += \
                    ${PAL_BASE} \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Test/Unity \


# Generate the revision (version) file automatically during the make process.
AUTO_GEN_REVISION_HEADER := no

# This is a top-level module
IS_TOP_LEVEL := yes

# code is not in one "src/" directory as SDK expects by default
USE_DIFFERENT_SOURCE_LAYOUT := yes
USE_DIFFERENT_SOURCE_LAYOUT_ARM := yes

# Generates the CoolWatcher headers automatically.
AUTO_XMD2H ?= no



# tests
C_SRC += ${wildcard PAL_Modules/*.c}
C_SRC += ${wildcard PAL_Modules/Crypto/*.c}
C_SRC += ${wildcard PAL_Modules/Networking/*.c}
C_SRC += ${wildcard PAL_Modules/RTOS/*.c}
C_SRC += ${wildcard PAL_Modules/FileSystem/*.c}
C_SRC += ${wildcard PAL_Modules/Sanity/*.c}
C_SRC += ${wildcard PAL_Modules/SOTP/*.c}
C_SRC += ${wildcard PAL_Modules/Storage/*.c}
C_SRC += ${wildcard PAL_Modules/Time/*.c}
C_SRC += ${wildcard PAL_Modules/TLS/*.c}
C_SRC += ${wildcard PAL_Modules/Update/*.c}
C_SRC += ${wildcard PAL_Modules/ROT/*.c}
C_SRC += ${wildcard PAL_Modules/DRBG/*.c}

# test runners (main())
# Not used here, as the tests are currently used by direct entrypoint calls, 
# not as separate executables.


# Unity framework is split into separate lib


## ------------------------------------- ##
##  Do Not touch below this line         ##
## ------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilerules.mk
