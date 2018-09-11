
cmake_minimum_required(VERSION 2.8)
project("fcc")

include(common_includes.cmake)

# Root dir - any specific path from root may be provided 
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Needed by update since FCC does not exist inside mbed-cloud-client anymore
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager)

# esfs
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux)

# mbed-trace
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace/mbed-trace)

# certificate enrollment
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-cloud-client/certificate-enrollment-client/source/include)

# nanostack
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/mbed-client-libservice)

# FIXME: remove this line once MCC swallows CEC
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-cloud-client/certificate-enrollment-client/certificate-enrollment-client)

SET(SOURCE_LIST "")

FOREACH(module ${MODULES})
	# sources
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module}/*.h")
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.c")
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.cpp")
ENDFOREACH()

FILE(GLOB factory-configurator-client ${SOURCE_LIST})

message("*********************************************************************")
message("factory-configurator-client = [[${factory-configurator-client}]]")
message("*********************************************************************")

CREATE_LIBRARY(factory-configurator-client "${factory-configurator-client}" "")

ADDSUBDIRS()
