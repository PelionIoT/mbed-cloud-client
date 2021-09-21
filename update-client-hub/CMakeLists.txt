INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING
cmake_minimum_required (VERSION 3.5)
SET(CMAKE_SYSTEM_NAME Generic)

if (FOTA_ENABLE)
  # using new FOTA implementation, disabling the old linking.
  return()
endif()

SET(UPDATE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

project(update-client)

# Add just the base of update-client and the shared part of modules to global include path.
# This helps a lot in keeping the global include path small as the global includes really
# are given to every single source module, even though the include files themselves really
# are accessed by update-client with very clean and precise manner.
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR})
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/atomic-queue)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/common)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/metadata-header)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/control-center)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/monitor)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/paal)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-http)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-local-file)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/delta-paal)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-local-file)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/delta-tool-internal/include)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/delta-tool-internal/source)


include_directories(${UPDATE_SOURCE_DIR}/update-client-hub)
include_directories(${UPDATE_SOURCE_DIR}/modules/atomic-queue/atomic-queue)
include_directories(${UPDATE_SOURCE_DIR}/modules/common/update-client-common)
include_directories(${UPDATE_SOURCE_DIR}/modules/metadata-header/update-client-metadata-header)
include_directories(${UPDATE_SOURCE_DIR}/modules/resume-engine)
include_directories(${UPDATE_SOURCE_DIR}/modules/resume-engine/resume-engine)
include_directories(${UPDATE_SOURCE_DIR}/modules/control-center/update-client-control-center)
include_directories(${UPDATE_SOURCE_DIR}/modules/device-identity)
include_directories(${UPDATE_SOURCE_DIR}/modules/device-identity/pal4life-device-identity)
include_directories(${UPDATE_SOURCE_DIR}/modules/firmware-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/firmware-manager/update-client-firmware-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/update-client-lwm2m)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager/update-client-manifest-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager/source)
include_directories(${UPDATE_SOURCE_DIR}/modules/monitor/update-client-monitor)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal-update-api)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal-update-api/paal-update-api)
include_directories(${UPDATE_SOURCE_DIR}/modules/source/update-client-source)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http/update-client-source-http)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http-socket)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http-socket/update-client-source-http-socket)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-local-file)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-local-file/update-client-source-local-file)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-manager/update-client-source-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal/update-client-paal)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-filesystem)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-filesystem/update-client-pal-filesystem)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap/update-client-pal-flashiap)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot/update-client-pal-flashiap-mcuboot)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-linux)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-linux/update-client-pal-linux)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-blockdevice/)
include_directories(${UPDATE_SOURCE_DIR}/modules/delta-paal/update-client-delta-paal)
include_directories(${UPDATE_SOURCE_DIR}/delta-tool-internal/include)

# XXX: currently only the Linux target builds out of the cmake environments, so
# let's ignore most of the code on other OS'.
#
# Note: the library needs to have _some_ source file in it, so on else branch
# the most generic ones are added to it.
#
# Note2: the created library is not really useful, but with it, the consumer side,
# eg. mbed-cloud-client and re-use the include declarations the library has and
# it does not need to have local include_directories() statements for cases when
# the update client is not really functional.
if (${OS_BRAND} MATCHES "Linux")
FILE(GLOB UPDATE_SRC
    "${UPDATE_SOURCE_DIR}/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/atomic-queue/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/common/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/metadata-header/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/resume-engine/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/control-center/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/device-identity/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/firmware-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/manifest-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-http/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-http-socket/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-local-file/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-filesystem/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/pal-linux/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/delta-paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/delta-tool-internal/source/*.c"
)
else()
FILE(GLOB UPDATE_SRC
    "${UPDATE_SOURCE_DIR}/delta-tool-internal/source/*.c"
    "${UPDATE_SOURCE_DIR}/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/atomic-queue/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/common/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/metadata-header/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/control-center/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/delta-paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/device-identity/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/firmware-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/manifest-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap-mcuboot/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/pal-blockdevice/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-blockdevice/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/delta-paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/delta-tool-internal/source/*.c"
)
endif()

# log the source list as other components do. Sometimes this is useful.
message("update-client = ${UPDATE_SRC}")

# create a library and describe its dependencies
add_library(update-client STATIC "${UPDATE_SRC}")
add_dependencies(update-client mbedclient mbedTrace mbedcrypto mbedx509 pal)
target_link_libraries(update-client mbedclient mbedTrace mbedcrypto mbedx509 pal)

# add pal dependency only for full client builds
if (NOT ${BUILD_TYPE} STREQUAL "client-lite")
    add_dependencies(update-client pal)
    target_link_libraries(update-client pal)
endif()
