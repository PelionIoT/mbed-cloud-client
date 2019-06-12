## ----------------------------------------------------------- ##
## Don't touch the next line unless you know what you're doing.##
## ----------------------------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilevars.mk

# Name of the module
LOCAL_NAME := ${MBED_CLOUD_SERVICE}/mbed-cloud-client

# list all modules APIs that are necessary to compile this module
LOCAL_API_DEPENDS := \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client \
                    ${API_PLATFORM_DEPENDS} \

# eww, root of the parent, used to fetch the config file
LOCAL_ADD_INCLUDE += \
                    ${MBED_CLOUD_SERVICE} \

LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME} \
                    ${LOCAL_NAME}/mbed-cloud-client \
                    ${LOCAL_NAME}/source \
                    ${LOCAL_NAME}/source/include \
                    ${LOCAL_NAME}/mbed-client \
                    ${LOCAL_NAME}/mbed-client/source \
                    ${LOCAL_NAME}/mbed-client/source/include \
                    ${LOCAL_NAME}/mbed-client/mbed-client \
                    ${LOCAL_NAME}/mbed-client/mbed-client-c \
                    ${LOCAL_NAME}/mbed-client/mbed-client-c/nsdl-c \
                    ${LOCAL_NAME}/mbed-client/mbed-client-c/source/include \
                    ${LOCAL_NAME}/mbed-coap \
                    ${LOCAL_NAME}/mbed-coap/mbed-coap \
                    ${LOCAL_NAME}/mbed-coap/source/include \
                    ${LOCAL_NAME}/mbed-client/mbed-client-classic \
                    ${LOCAL_NAME}/mbed-client/mbed-client-classic/mbed-client-classic \
                    ${LOCAL_NAME}/mbed-client/mbed-client-mbed-tls \
                    ${LOCAL_NAME}/mbed-client/mbed-client-mbed-tls/mbed-client-mbed-tls \
                    
# misc dependencies
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/mbed-trace \
                    ${LOCAL_NAME}/nanostack-libservice \
                    ${LOCAL_NAME}/nanostack-libservice/mbed-client-libservice \
                    ${LOCAL_NAME}/ns-hal-pal \
                    ${LOCAL_NAME}/sal-stack-nanostack-eventloop/nanostack-event-loop \
                    ${LOCAL_NAME}/mbed-client-randlib/mbed-client-randlib \

# PAL
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/mbed-client-pal \
                    ${LOCAL_NAME}/mbed-client-pal/Configs/pal_config \
                    ${LOCAL_NAME}/mbed-client-pal/Configs/pal_config/SXOS \
                    ${LOCAL_NAME}/mbed-client-pal/Source/PAL-Impl/Services-API \
                    ${LOCAL_NAME}/mbed-client-pal/Source \
                    ${LOCAL_NAME}/mbed-client-pal/Source/Port/Platform-API \
# update client
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/update-client-hub \
                    ${LOCAL_NAME}/update-client-hub/source \
                    ${LOCAL_NAME}/update-client-hub/modules/atomic-queue \
                    ${LOCAL_NAME}/update-client-hub/modules/common \
                    ${LOCAL_NAME}/update-client-hub/modules/common/update-client-common \
                    ${LOCAL_NAME}/update-client-hub/modules/control-center \
                    ${LOCAL_NAME}/update-client-hub/modules/device-identity \
                    ${LOCAL_NAME}/update-client-hub/modules/firmware-manager \
                    ${LOCAL_NAME}/update-client-hub/modules/lwm2m-mbed \
                    ${LOCAL_NAME}/update-client-hub/modules/lwm2m-mbed/update-client-lwm2m \
                    ${LOCAL_NAME}/update-client-hub/modules/manifest-manager \
                    ${LOCAL_NAME}/update-client-hub/modules/metadata-header \
                    ${LOCAL_NAME}/update-client-hub/modules/monitor \
                    ${LOCAL_NAME}/update-client-hub/modules/paal \
                    ${LOCAL_NAME}/update-client-hub/modules/pal-filesystem \
                    ${LOCAL_NAME}/update-client-hub/modules/resume-engine \
                    ${LOCAL_NAME}/update-client-hub/modules/source \
                    ${LOCAL_NAME}/update-client-hub/modules/source-http \
                    ${LOCAL_NAME}/update-client-hub/modules/source-http-socket \
                    ${LOCAL_NAME}/update-client-hub/modules/source-local-file \
                    ${LOCAL_NAME}/update-client-hub/modules/source-manager \
                    platform/include/fota \

# FCC, unfortunately we need to keep most of the directories here as
# public header files include their internal dependency headers without
# paths.
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/factory-configurator-client/factory-configurator-client/factory-configurator-client \
                    ${LOCAL_NAME}/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler \
                    ${LOCAL_NAME}/factory-configurator-client/key-config-manager \
                    ${LOCAL_NAME}/factory-configurator-client/key-config-manager/key-config-manager \
                    ${LOCAL_NAME}/factory-configurator-client/key-config-manager/source/include \
                    ${LOCAL_NAME}/factory-configurator-client/factory-configurator-client/source/include \
                    ${LOCAL_NAME}/factory-configurator-client/mbed-client-esfs/source/include \
                    ${LOCAL_NAME}/factory-configurator-client/utils/utils \
                    ${LOCAL_NAME}/factory-configurator-client/logger/logger \
                    ${LOCAL_NAME}/factory-configurator-client/crypto-service/source/include \
                    ${LOCAL_NAME}/factory-configurator-client/crypto-service/crypto-service \
                    ${LOCAL_NAME}/factory-configurator-client/storage/storage \
                    ${LOCAL_NAME}/factory-configurator-client/storage/source/include \
                    ${LOCAL_NAME}/certificate-enrollment-client/source/include \

# certificate enrollment client
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/certificate-enrollment-client/certificate-enrollment-client

# Compile the sub-modules, except when the "service" must be used as a library.
# list all the modules that need to be compiled prior to using this module
LOCAL_MODULE_DEPENDS += ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal

LOCAL_MODULE_DEPENDS += ${MBED_CLOUD_SERVICE}/mbed-cloud-client/factory-configurator-client


LOCAL_EXPORT_FLAG += __SXOS__

LOCAL_EXPORT_FLAG += "MBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=8192"
LOCAL_EXPORT_FLAG += "MBED_CONF_NANOSTACK_EVENTLOOP_EXCLUDE_HIGHRES_TIMER=1"
LOCAL_EXPORT_FLAG += "NS_EXCLUDE_HIGHRES_TIMER=1"
LOCAL_EXPORT_FLAG += "MBED_CONF_NANOSTACK_EVENTLOOP_USE_PLATFORM_TICK_TIMER"
LOCAL_EXPORT_FLAG += "NS_EVENTLOOP_USE_TICK_TIMER"



# Disable code using STL as it not available on SDK
LOCAL_EXPORT_FLAG += "MBED_CLOUD_CLIENT_STL_API=0"
LOCAL_EXPORT_FLAG += "MBED_CLOUD_CLIENT_STD_NAMESPACE_POLLUTION=0"

# Update client
LOCAL_EXPORT_FLAG += "ATOMIC_QUEUE_USE_PAL=1"
LOCAL_EXPORT_FLAG += "ARM_UC_PROFILE_MBED_CLOUD_CLIENT=1"
LOCAL_EXPORT_FLAG += "ARM_UC_FEATURE_PAL_FILESYSTEM=1"
LOCAL_EXPORT_FLAG += "MBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL=MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP"

# Generate the revision (version) file automatically during the make process.
AUTO_GEN_REVISION_HEADER := no

# This is a top-level module
IS_TOP_LEVEL := yes

# code is not in one "src/" directory as SDK expects by default
USE_DIFFERENT_SOURCE_LAYOUT := yes
USE_DIFFERENT_SOURCE_LAYOUT_ARM := yes

# Generates the CoolWatcher headers automatically.
AUTO_XMD2H ?= no

C_SRC := ${wildcard source/*.c}
C++_SRC := ${wildcard source/*.cpp} 
C_SRC += ${wildcard mbed-client/source/*.c}
C++_SRC += ${wildcard mbed-client/source/*.cpp}
C++_SRC += ${wildcard mbed-client/mbed-client-c/source/*.cpp}
C++_SRC += ${wildcard mbed-client/mbed-client-classic/source/*.cpp}
C++_SRC += ${wildcard mbed-client/mbed-client-mbed-tls/source/*.cpp}
C++_SRC += ${wildcard ns-hal-pal/*.cpp}

C_SRC += ${wildcard mbed-client-randlib/source/*.c}
C_SRC += ${wildcard mbed-coap/source/*.c}
C_SRC += ${wildcard mbed-client/mbed-client-c/source/*.c}
C_SRC += ${wildcard nanostack-libservice/source/libBits/*.c}
C_SRC += ${wildcard nanostack-libservice/source/libList/*.c}
C_SRC += ${wildcard nanostack-libservice/source/nsdynmemLIB/*.c}
C_SRC += ${wildcard ns-hal-pal/*.c}
C_SRC += ${wildcard sal-stack-nanostack-eventloop/source/*.c}

# Update client
C_SRC += ${wildcard update-client-hub/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/atomic-queue/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/common/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/resume-engine/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/control-center/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/device-identity/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/firmware-manager/source/*.c}
C++_SRC += ${wildcard update-client-hub/modules/lwm2m-mbed/source/*.cpp}
C_SRC += ${wildcard update-client-hub/modules/lwm2m-mbed/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/manifest-manager/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/metadata-header/source/*.c}
#C_SRC += ${wildcard update-client-hub/modules/source-http/source/*.c}
#C_SRC += ${wildcardupdate-client-hub/ modules/source-http-socket/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/source-manager/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/paal/source/*.c}
C_SRC += ${wildcard update-client-hub/modules/pal-filesystem/source/*.c}

# Todo: the CE might need to be separated also
C_SRC += ${wildcard certificate-enrollment-client/source/*.c}
C++_SRC += ${wildcard certificate-enrollment-client/source/*.cpp}

# mbed-trace and its dependency. This might deserver a separate lib, but the mbed-trace 
# already has a makefile and mixing this system with generic make takes a bit more work 
# than deemed necessary for two C-files.
C_SRC += ${wildcard mbed-trace/source/*.c}
C_SRC += ${wildcard nanostack-libservice/source/libip6string/*.c}

## ------------------------------------- ##
##  Do Not touch below this line         ##
## ------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilerules.mk
