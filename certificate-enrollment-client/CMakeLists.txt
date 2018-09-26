cmake_minimum_required(VERSION 2.6)
project("certificate-enrollment-client")

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/include)

FILE(
	GLOB_RECURSE  
	certificate_enrollment_client

	"${CMAKE_CURRENT_SOURCE_DIR}/certificate-enrollment-client/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp"
)

message ("*********************************************************************")
message ("certificate_enrollment_client = [[${certificate_enrollment_client}]]")
message ("*********************************************************************")

CREATE_LIBRARY(certificate-enrollment-client "${certificate_enrollment_client}" "")

ADDSUBDIRS()
