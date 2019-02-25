## ----------------------------------------------------------- ##
## Don't touch the next line unless you know what you're doing.##
## ----------------------------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilevars.mk


# Name of the module
LOCAL_NAME := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client

# list all modules APIs that are necessary to compile this module
LOCAL_API_DEPENDS := \
                    ${API_PLATFORM_DEPENDS} \

# Root of the parent to include path, used to fetch the config files
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE} \

# misc dependencies
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-trace/mbed-trace \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/nanostack-libservice/mbed-client-libservice \

# a direct dependency on mbedtls?!
LOCAL_ADD_INCLUDE += \
                    platform/service/net/mbedtls/src/mbedtls/include/mbedtls \

# PAL
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Configs/pal_config \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Configs/pal_config/SXOS \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Source/PAL-Impl/Services-API \

# CE
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/certificate-enrollment-client/source/include \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/certificate-enrollment-client/certificate-enrollment-client

# FCC
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/crypto-service/source/include \
                    ${LOCAL_NAME}/crypto-service/crypto-service \
                    ${LOCAL_NAME}/factory-configurator-client/factory-configurator-client \
                    ${LOCAL_NAME}/factory-configurator-client/source/include \
                    ${LOCAL_NAME}/fcc-bundle-handler/fcc-bundle-handler \
                    ${LOCAL_NAME}/fcc-bundle-handler/source/include \
                    ${LOCAL_NAME}/fcc-output-info-handler/fcc-output-info-handler \
                    ${LOCAL_NAME}/key-config-manager/key-config-manager \
                    ${LOCAL_NAME}/key-config-manager/source/include \
                    ${LOCAL_NAME}/logger/logger \
                    ${LOCAL_NAME}/mbed-client-esfs/source/include \
                    ${LOCAL_NAME}/utils/utils \
                    ${LOCAL_NAME}/storage/storage \
                    ${LOCAL_NAME}/secsrv-cbor/secsrv-cbor \


# this should already come via inheritance, but let's be clear
LOCAL_EXPORT_FLAG += __SXOS__

# This is needed to disable (unused?) references to functions which are not available on sdk,
# namely ldexp(), isgreater() and isless().
LOCAL_EXPORT_FLAG += "CBOR_NO_FLOAT"

# Generate the revision (version) file automatically during the make process.
AUTO_GEN_REVISION_HEADER := no

# This is not a top-level module, ie. dependency submodules are not built into this archive
IS_TOP_LEVEL := no

# code is not in one "src/" directory as SDK expects by default
USE_DIFFERENT_SOURCE_LAYOUT := yes
USE_DIFFERENT_SOURCE_LAYOUT_ARM := yes

# Generates the CoolWatcher headers automatically.
AUTO_XMD2H ?= no


# FCC, may be split into smaller libs if needed
C_SRC += ${wildcard crypto-service/source/*.c}
C_SRC += ${wildcard factory-configurator-client/source/*.c}
C_SRC += ${wildcard fcc-bundle-handler/source/*.c}
C_SRC += ${wildcard fcc-output-info-handler/source/*.c}
C_SRC += ${wildcard key-config-manager/source/*.c}
C_SRC += ${wildcard mbed-client-esfs/source/*.c}
C_SRC += ${wildcard mbed-client-esfs/source/sotp/*.c}
C_SRC += ${wildcard mbed-trace-helper/source/*.c}
C_SRC += ${wildcard utils/source/*.c}
C_SRC += ${wildcard secsrv-cbor/source/*.c}
C_SRC += ${wildcard storage/source/*.c}


## ------------------------------------- ##
##  Do Not touch below this line         ##
## ------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilerules.mk
