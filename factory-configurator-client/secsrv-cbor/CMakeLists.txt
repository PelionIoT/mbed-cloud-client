
# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/secsrv-cbor)

FILE(
	GLOB_RECURSE  
	cbor

	"${CMAKE_CURRENT_SOURCE_DIR}/secsrv-cbor/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
)

message ("*********************************************************************")
message ("cbor = [[${cbor}]]")
message ("*********************************************************************")

CREATE_LIBRARY(cn-cbor "${cbor}" "")
ADDSUBDIRS()