
cmake_minimum_required (VERSION 3.5)

# includes
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/src)

FILE(
	GLOB_RECURSE  
	tinycbor

	"${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

message ("*********************************************************************")
message ("tinycbor = [[${tinycbor}]]")
message ("*********************************************************************")

CREATE_LIBRARY(tinycbor "${tinycbor}" "")

ADDSUBDIRS()