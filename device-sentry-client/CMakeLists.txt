cmake_minimum_required(VERSION 2.6)
project("device-sentry-client")

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/device-sentry-client)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/linux-os)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test-api)

if (${OS_BRAND} MATCHES "Linux")
FILE(
	GLOB_RECURSE  
	device_sentry_client

	"${CMAKE_CURRENT_SOURCE_DIR}/source/ds_metrics_report.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/DeviceSentryClient.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/linux-os/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/linux-os/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/test-api/*.c"	
	"${CMAKE_CURRENT_SOURCE_DIR}/test-api/*.cpp"
)
else()
FILE(
	GLOB_RECURSE  
	device_sentry_client

	"${CMAKE_CURRENT_SOURCE_DIR}/source/ds_metrics_report.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/DeviceSentryClient.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/stub-os/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/stub-os/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/test-api/*.c"	
	"${CMAKE_CURRENT_SOURCE_DIR}/test-api/*.cpp"
)
endif()

message ("*********************************************************************")
message ("device_sentry_client = [[${device_sentry_client}]]")
message ("*********************************************************************")

CREATE_LIBRARY(device-sentry-client "${device_sentry_client}" "")

ADDSUBDIRS()
