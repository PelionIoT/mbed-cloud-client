cmake_minimum_required(VERSION 2.6)
project("certificate-enrollment-client")

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/certificate-enrollment-client)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/include)

# FIXME: remove this line once integration is done
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../mbed-cloud-client/source/include)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../source/include)

# For mock EST
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/TESTS/utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../pal-platform/Middleware/mbedtls/mbedtls/include/mbedtls)

FILE(
	GLOB_RECURSE  
	certificate_enrollment_client

	"${CMAKE_CURRENT_SOURCE_DIR}/certificate-enrollment-client/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp"
	
	# Fixme: Mock EST
	"${CMAKE_CURRENT_SOURCE_DIR}/TESTS/utils/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/TESTS/utils/*.c"
)

message ("*********************************************************************")
message ("certificate_enrollment_client = [[${certificate_enrollment_client}]]")
message ("*********************************************************************")

CREATE_LIBRARY(certificate-enrollment-client "${certificate_enrollment_client}" "")
ADDSUBDIRS()
