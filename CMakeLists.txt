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
add_definitions(-DPAL_IGNORE_UNIQUE_THREAD_PRIORITY)

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

# includes
FOREACH(module ${FCC_MODULES})
    ADD_GLOBALDIR(${FACTORY_CLIENT_SOURCE_DIR}/${module}/${module})
    ADD_GLOBALDIR(${FACTORY_CLIENT_SOURCE_DIR}/${module}/source/include)
ENDFOREACH()

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

# update-client

SET(UPDATE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/update-client-hub)

ADD_GLOBALDIR(${UPDATE_SOURCE_DIR})
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/update-client-hub)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/atomic-queue)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/atomic-queue/atomic-queue)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/common)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/common/update-client-common)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/control-center)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/control-center/update-client-control-center)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/device-identity)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/device-identity/pal4life-device-identity)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/firmware-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/firmware-manager/update-client-firmware-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/update-client-lwm2m)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/manifest-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/manifest-manager/update-client-manifest-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/manifest-manager/source)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/monitor)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/monitor/update-client-monitor)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/paal-update-api)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/paal-update-api/paal-update-api)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source/update-client-source)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-http)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-http/update-client-source-http)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-http-socket)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-http-socket/update-client-source-http-socket)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/source-manager/update-client-source-manager)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/paal)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/paal/update-client-paal)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-filesystem)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-filesystem/update-client-pal-filesystem)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-flashiap)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-flashiap/update-client-pal-flashiap)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-linux)
ADD_GLOBALDIR(${UPDATE_SOURCE_DIR}/modules/pal-linux/update-client-pal-linux)

FILE(GLOB MBED_CLOUD_CLIENT_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-c/source/*.c"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-classic/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-mbed-tls/source/*.cpp"

    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap/source/*.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib/source/*.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.cpp"

    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libBits/common_functions.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libList/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/nsdynmemLIB/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/source/libip6string/ip6tos.c"

    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/ns_event_loop.c"
if ((${OS_BRAND} MATCHES "FreeRTOS"))
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_random.c"
endif()
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/ns_hal_init.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_interrupt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/ns-hal-pal/arm_hal_timer.cpp"
    "${FACTORY_CLIENT_SOURCE_DIR}/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/storage/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/secure_store/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/key-config-manager/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/utils/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/logger/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux/*.cpp"
    "${FACTORY_CLIENT_SOURCE_DIR}/crypto-service/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/fcc-bundle-handler/source/*.c"
    "${FACTORY_CLIENT_SOURCE_DIR}/fcc-output-info-handler/source/*.c"
    )

if ((${OS_BRAND} MATCHES "Linux"))
    FILE(GLOB UPDATE_SRC
    "${UPDATE_SOURCE_DIR}/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/atomic-queue/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/common/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/control-center/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/device-identity/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/firmware-manager/source/*.c"
    "${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed/source/*.cpp"
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

CREATE_LIBRARY(mbedCloudClient "${MBED_CLOUD_CLIENT_SRC}" "")
add_dependencies(mbedCloudClient mbedtls)

ADDSUBDIRS()
