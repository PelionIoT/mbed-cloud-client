cmake_minimum_required(VERSION 2.6)
project("fcc")

include(common_includes.cmake)

# esfs
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux)

# mbed-tace
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-trace/mbed-trace)

# nanostack
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/nanostack-libservice/mbed-client-libservice)

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
