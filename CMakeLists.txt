INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING
cmake_minimum_required (VERSION 3.5)
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
ADD_GLOBALDIR(${PAL_SOURCE_DIR})
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
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/tinycbor/src)

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
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/storage/source/include)
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
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-bundle-handler/fcc-bundle-handler)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-bundle-handler/source/include)
include_directories(${FACTORY_CLIENT_SOURCE_DIR}/fcc-output-info-handler/fcc-output-info-handler)

# Certificate Enrollment Client
SET(CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/certificate-enrollment-client)
ADD_GLOBALDIR(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/certificate-enrollment-client)
include_directories(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/certificate-enrollment-client)
include_directories(${CERTIFICATE_ENROLLMENT_CLIENT_SOURCE_DIR}/source/include)

# Secure Device Access Client
SET(SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/secure-device-access-client)
ADD_GLOBALDIR(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/secure-device-access/secure-device-access)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/logger/logger)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/helpers/helpers)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/mem/mem)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/platform/platform)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/sda-bundle-parser/sda-bundle-parser)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/secure-device-access/secure-device-access)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/sda-cose/sda-cose)
include_directories(${SECURE_DEVICE_ACCESS_CLIENT_SOURCE_DIR}/cose-c/cose-c)

# Update client

SET(UPDATE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/update-client-hub)

include_directories(${UPDATE_SOURCE_DIR})
include_directories(${UPDATE_SOURCE_DIR}/modules/atomic-queue)
include_directories(${UPDATE_SOURCE_DIR}/modules/common)
include_directories(${UPDATE_SOURCE_DIR}/modules/control-center)
include_directories(${UPDATE_SOURCE_DIR}/modules/lwm2m-mbed)
include_directories(${UPDATE_SOURCE_DIR}/modules/monitor)
include_directories(${UPDATE_SOURCE_DIR}/modules/paal)
include_directories(${UPDATE_SOURCE_DIR}/modules/source)
include_directories(${UPDATE_SOURCE_DIR}/modules/source-http)


FILE(GLOB MBED_CLOUD_CLIENT_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp"
)

FILE(GLOB MBED_CLIENT_SRC
    "${MBED_CLIENT_SOURCE_DIR}/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/source/*.c"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-c/source/*.c"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-classic/source/*.cpp"
    "${MBED_CLIENT_SOURCE_DIR}/mbed-client-mbed-tls/source/*.cpp"
)

FILE(GLOB MBED_CLIENT_RANDLIB_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-randlib/source/*.c"
)

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

# eventloop library
FILE(GLOB NANOSTACK_EVENTLOOP_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/sal-stack-nanostack-eventloop/source/*.cpp"
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

# mbed-coap library
FILE(GLOB MBED_COAP_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/mbed-coap/source/*.c"
)

message("MbedCloudClient sources = \n ${MBED_CLOUD_CLIENT_SRC}")

# Note: this is not using the CREATE_LIBRARY() on purpose, as it would pollute all the
# executables with the library.

add_library(nshalpal STATIC "${NS_HAL_PAL_SRC}")

# ns-hal-pal uses PAL API's, so create dependency on them
add_dependencies(nshalpal pal)
target_link_libraries(nshalpal pal)

# nanostack-libservice is depending only of ns-hal (via platform_critical_*()), which is fulfilled
# by ns-hal-pal.
add_library(nanostacklibservice STATIC "${NANOSTACK_LIBSERVICE_SRC}")
add_dependencies(nanostacklibservice nshalpal)
target_link_libraries(nanostacklibservice nshalpal)

# libservice is needed for ns-list and nsdynmem, so add dependencies
add_library(nanostackeventloop STATIC "${NANOSTACK_EVENTLOOP_SRC}")
add_dependencies(nanostackeventloop nanostacklibservice)
target_link_libraries(nanostackeventloop nanostacklibservice)

# randlib depends only on ns-hal-pal
add_library(mbedclientrandlib STATIC "${MBED_CLIENT_RANDLIB_SRC}")
add_dependencies(mbedclientrandlib nshalpal)
target_link_libraries(mbedclientrandlib nshalpal)

# libservice is needed for ns-list and nsdynmem, so add dependencies for that
add_library(mbedcoap STATIC "${MBED_COAP_SRC}")
add_dependencies(mbedcoap nanostacklibservice mbedTrace mbedclientrandlib)
target_link_libraries(mbedcoap nanostacklibservice mbedTrace mbedclientrandlib)

add_library(mbedclient STATIC "${MBED_CLIENT_SRC}")
add_dependencies(mbedclient nanostacklibservice nanostackeventloop mbedcoap mbedTrace)
target_link_libraries(mbedclient nanostacklibservice nanostackeventloop mbedcoap mbedTrace)

CREATE_LIBRARY(mbedCloudClient "${MBED_CLOUD_CLIENT_SRC}" "")

# Create buld dependencies to ensure all the needed parts get build
add_dependencies(mbedCloudClient pal factory-configurator-client mbedTrace nanostacklibservice nanostackeventloop mbedclient certificate-enrollment-client update-client)

# Add linking dependency for all the subcomponents of mbedCloudClient. This allows one to
# just have "target_link_libraries(<client-application> mbedCloudClient)" and cmake will
# automatically build all the submodules.
target_link_libraries(mbedCloudClient pal factory-configurator-client mbedTrace nanostacklibservice nanostackeventloop mbedclient certificate-enrollment-client update-client)

ADDSUBDIRS()

