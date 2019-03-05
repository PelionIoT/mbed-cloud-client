INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING
cmake_minimum_required (VERSION 2.8)
SET(CMAKE_SYSTEM_NAME Generic)

add_definitions(-DTARGET_LIKE_POSIX)

if (${OS_BRAND} MATCHES Linux)
    add_definitions(-DMBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=102400)
else()
    add_definitions(-DMBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=8000)
endif()


SET(MBED_CLOUD_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbed-cloud-client)

add_definitions(-DMBED_CONF_NANOSTACK_EVENTLOOP_EXCLUDE_HIGHRES_TIMER)
add_definitions(-DMBED_CONF_NANOSTACK_EVENTLOOP_USE_PLATFORM_TICK_TIMER)

add_definitions(-DARM_UC_PROFILE_MBED_CLOUD_CLIENT=1)
add_definitions(-DARM_UC_FEATURE_PAL_FILESYSTEM=1)

# enable duplicate detection by default, count is the same as resend queue size
add_definitions(-DMBED_CONF_MBED_CLIENT_SN_COAP_DUPLICATION_MAX_MSGS_COUNT=4)

project(mbedCloudClient)

# mbed-cloud-client

ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR})
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/source)
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/source/include)
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/mbed-cloud-client)
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/mbed-client)

# mbed-client

SET(MBED_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbed-client)

ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR})
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/source)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/source/include)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-c)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-c/nsdl-c)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-c/source/include)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-classic)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-classic/mbed-client-classic)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-mbed-tls)
ADD_GLOBALDIR(${MBED_CLIENT_SOURCE_DIR}/mbed-client-mbed-tls/mbed-client-mbedtls)

# pal headers

SET(PAL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-pal/Source)
ADD_GLOBALDIR(${PAL_SOURCE_DIR}/PAL-Impl/Services-API)
ADD_GLOBALDIR(${PAL_SOURCE_DIR}/Port/Platform-API)

# common components

ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap/mbed-coap)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace/mbed-trace)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib/mbed-client-randlib)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib/mbed-client-randlib/platform)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/mbed-client-libservice)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/mbed-client-libservice/platform)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/nanostack-event-loop)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal)

# factory-client

SET(FACTORY_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/factory-configurator-client)
ADD_GLOBALDIR(${FACTORY_CLIENT_SOURCE_DIR}/factory-configurator-client)

SET(FCC_MODULES
    ftcd-comm-base
    ftcd-comm-socket
    crypto-service
    key-config-manager
    factory-configurator-client
    fcc-bundle-handler
    secsrv-cbor
    logger
    storage
    utils
    mbed-trace-helper
    fcc-output-info-handler
    mbed-client-esfs
)

# XXX: do NOT do this, no need to spam ~5KB of FCC include paths for each CC/CXX invocation. 
# includes
#FOREACH(module ${FCC_MODULES})
#    ADD_GLOBALDIR(${FACTORY_CLIENT_SOURCE_DIR}/${module}/${module})
#    ADD_GLOBALDIR(${FACTORY_CLIENT_SOURCE_DIR}/${module}/source/include)
#ENDFOREACH()

include_directories(${FACTORY_CLIENT_SOURCE_DIR}/factory-configurator-client/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/factory-configurator-client/factory-configurator-client)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fc_protocol_handler/fc_protocol_handler)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fc_protocol_handler/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/secure_store)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/secure_store/secure_store)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/storage)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/storage/storage)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/key-config-manager)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/key-config-manager/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/utils)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/utils/utils)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/logger)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/logger/logger)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source-pal/api)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/crypto-service/crypto-service)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/crypto-service/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/secsrv-cbor/secsrv-cbor)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-bundle-handler/fcc-bundle-handler)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-bundle-handler/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-output-info-handler/fcc-output-info-handler)

# Certificate Enrollment Client
SET(CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/certificate-enrollment-client)
ADD_GLOBALDIR(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/certificate-enrollment-client)
include_directories(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/certificate-enrollment-client)
include_directories(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/source/include)

# update-client

SET(UPDATE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/update-client-hub)

# Add just the base of update-client and the shared part of modules to global include path.
# This helps a lot in keeping the global include path small as the global includes really
# are given to every single source module, even though the include files themselves really 
# are accessed by update-client with very clean and precise manner. 
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR})
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/common)

include_directories(${UPDATE_SOURCE_DIR})
include_directories(${UPDATE_SOURCE_DIR}/update-client-hub)
include_directories(${UPDATE_SOURCE_DIR}/modules/atomic-queue)
include_directories(${UPDATE_SOURCE_DIR}/modules/atomic-queue/atomic-queue)
include_directories(${UPDATE_SOURCE_DIR}/modules/common)
include_directories(${UPDATE_SOURCE_DIR}/modules/common/update-client-common)
include_directories(${UPDATE_SOURCE_DIR}/modules/resume-engine)
include_directories(${UPDATE_SOURCE_DIR}/modules/resume-engine/resume-engine)
include_directories(${UPDATE_SOURCE_DIR}/modules/control-center)
include_directories(${UPDATE_SOURCE_DIR}/modules/control-center/update-client-control-center)
include_directories(${UPDATE_SOURCE_DIR}/modules/device-identity)
include_directories(${UPDATE_SOURCE_DIR}/modules/device-identity/pal4life-device-identity)
include_directories(${UPDATE_SOURCE_DIR}/modules/firmware-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/firmware-manager/update-client-firmware-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed)
include_directories(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/update-client-lwm2m)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager/update-client-manifest-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/manifest-manager/source)
include_directories(${UPDATE_SOURCE_DIR}/modules/monitor)
include_directories(${UPDATE_SOURCE_DIR}/modules/monitor/update-client-monitor)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal-update-api)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal-update-api/paal-update-api)
include_directories(${UPDATE_SOURCE_DIR}/modules/source)
include_directories(${UPDATE_SOURCE_DIR}/modules/source/update-client-source)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http/update-client-source-http)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http-socket)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http-socket/update-client-source-http-socket)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-manager/update-client-source-manager)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal/update-client-paal)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-filesystem)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-filesystem/update-client-pal-filesystem)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-flashiap/update-client-pal-flashiap)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-linux)
include_directories(${UPDATE_SOURCE_DIR}/modules/pal-linux/update-client-pal-linux)

FILE(GLOB MBED_CLOUD_CLIENT_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/source/*.c"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-c/source/*.c"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-classic/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-mbed-tls/source/*.cpp"

    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap/source/*.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib/source/*.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.cpp"

    "${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/source/*.c"
    "${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/source/*.cpp"
)

if (${OS_BRAND} MATCHES AmigaOS)
# avoid "mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mconnectionhandlerpimpl.cpp:160:1: internal compiler error: in connect_traces, at dwarf2cfi.c:2752"
set_source_files_properties(../mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mconnectionhandlerpimpl.cpp PROPERTIES COMPILE_FLAGS -O0)
endif()

# This part gets split into separate nanostacklibservice, which is needed
# as the mbedTrace -library points to ip6tos and there is a dependency chain of
# pal->mbed-trace->nanostack-libservice. Without this, the PAL should add mbedCloudClient 
# as dependency and that would also create a circular dependency, which is a nightmare on linking time.
#
# Note: the native Makefile of nanostack-libservice will create a library called "libservice", 
# so just to avoid some collisions, name of the library created by this is different and matches
# the current name of the repository (nanostack-libservice).
FILE(GLOB NANOSTACK_LIBSERVICE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libBits/common_functions.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libList/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/nsdynmemLIB/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libip6string/ip6tos.c"
)

# these will go to nshalpal library
FILE(GLOB NS_HAL_PAL_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/ns_event_loop.c"
if ((${OS_BRAND} MATCHES "FreeRTOS"))
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_random.c"
endif()
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/ns_hal_init.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_interrupt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_timer.cpp"
)

# todo: make library out of the update client too
if ((${OS_BRAND} MATCHES "Linux"))
    FILE(GLOB UPDATE_SRC
    "${UPDATE_SOURCE_DIR}/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/atomic-queue/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/common/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/resume-engine/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/control-center/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/device-identity/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/firmware-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/manifest-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-http/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-http-socket/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/source-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/paal/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-filesystem/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/pal-flashiap/source/*.cpp"
    "${UPDATE_SOURCE_DIR}/modules/pal-linux/source/*.c"
    )
endif()

list(APPEND MBED_CLOUD_CLIENT_SRC ${UPDATE_SRC})
message(status "Mbed Cloud Client sources = \n ${MBED_CLOUD_CLIENT_SRC}")


CREATE_LIBRARY(nshalpal "${NS_HAL_PAL_SRC}" "")

# ns-hal-pal uses PAL API's, so create dependency on them
add_dependencies(nshalpal pal)
target_link_libraries(nshalpal pal)

# nanostack-libservice is depending only of ns-hal (via platform_critical_*()), which is fulfilled
# by ns-hal-pal.
CREATE_LIBRARY(nanostacklibservice "${NANOSTACK_LIBSERVICE_SRC}" "")
add_dependencies(nanostacklibservice nshalpal)

CREATE_LIBRARY(mbedCloudClient "${MBED_CLOUD_CLIENT_SRC}" "")

# Create buld dependencies to ensure all the needed parts get build
add_dependencies(mbedCloudClient mbedtls mbedcrypto mbedx509 factory-configurator-client esfs pal mbedTrace nanostacklibservice)

# Add linking dependency for all the subcomponents of mbedCloudClient. This allows one to
# just have "target_link_libraries(<client-application> mbedCloudClient)" and cmake will
# automatically build all the submodules.
target_link_libraries(mbedCloudClient pal mbedcrypto mbedx509 mbedtls factory-configurator-client esfs mbedTrace nshalpal nanostacklibservice)


ADDSUBDIRS()

