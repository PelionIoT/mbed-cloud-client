## ----------------------------------------------------------- ##
## Don't touch the next line unless you know what you're doing.##
## ----------------------------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilevars.mk

# Name of the module
LOCAL_NAME := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal/Test/Unity

PAL_BASE := ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal

# list all modules APIs that are necessary to compile this module
LOCAL_API_DEPENDS := \
                    ${MBED_CLOUD_SERVICE}/mbed-cloud-client/mbed-client-pal \
                    ${API_PLATFORM_DEPENDS} \

LOCAL_ADD_INCLUDE := \
                    ${PAL_BASE}/Source/PAL-Impl \
                    ${PAL_BASE}/Source/PAL-Impl/Services-API \
                    ${PAL_BASE}/Source/Port/Platform-API \
                    ${PAL_BASE}/Configs/pal_config \
                    ${PAL_BASE}/Configs/pal_config/SXOS \

# test related includes
LOCAL_ADD_INCLUDE += \
                    ${LOCAL_NAME}/src \
                    ${LOCAL_NAME}/extras/fixture/src \

# direct PAL to its OS specific config file
LOCAL_EXPORT_FLAG += "'PAL_USER_DEFINED_CONFIGURATION=\"SXOS/sxos_sotp.h\"'"

# XXX: try to remove reference to non-existing math.h
LOCAL_EXPORT_FLAG += UNITY_EXCLUDE_MATH_H

# Generate the revision (version) file automatically during the make process.
AUTO_GEN_REVISION_HEADER := no

# This is a top-level module
IS_TOP_LEVEL := no

# code is not in one "src/" directory as SDK expects by default
USE_DIFFERENT_SOURCE_LAYOUT := yes
USE_DIFFERENT_SOURCE_LAYOUT_ARM := yes

# Generates the CoolWatcher headers automatically.
AUTO_XMD2H ?= no

# Unity framework itself
C_SRC += ${wildcard src/*.c}
C_SRC += ${wildcard extras/fixture/src/*.c}

## ------------------------------------- ##
##  Do Not touch below this line         ##
## ------------------------------------- ##
include ${SOFT_WORKDIR}/env/compilation/compilerules.mk
