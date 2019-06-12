

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source/sotp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/extras/fixture/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../mbed-trace)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../nanostack-libservice/mbed-client-libservice)

# temp workaround
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../mbed-client-pal/Source/Port/Platform-API)

ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/source/include)

set (PAL_TESTS_SOURCE_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/../../mbed-client-pal/Test/Unitest)

#SET(SOTP_DEBUG_FLAGS "-DESFS_INTERACTIVE_TEST")
add_definitions(${SOTP_DEBUG_FLAGS})

add_definitions(-DRBP_TESTING)

FILE(
	GLOB_RECURSE  
	esfs_src
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
)

message ( "********************************************************************* ")
message ("esfs_src = [[${esfs_src}]]")
message ( "********************************************************************* ")

CREATE_LIBRARY(esfs "${esfs_src}" "")

add_dependencies(esfs palFilesystem palDRBG palCrypto palROT)
target_link_libraries(esfs palFilesystem palDRBG palCrypto palROT)

# Create own library for SOTP features
FILE(
	GLOB_RECURSE  
	sotp_src
	"${CMAKE_CURRENT_SOURCE_DIR}/source/sotp/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/sotp/*.h"
)

message ( "********************************************************************* ")
message ("sotp_src = [[${sotp_src}]]")
message ( "********************************************************************* ")

CREATE_LIBRARY(sotp "${sotp_src}" "")


if(DEFINED ENV{ESFS_TESTS_ENABLED})

# ESFS_TESTS_ENABLED is an environment variable.
# define ESFS_TESTS_ENABLED only if you would like to build ESFS unit-tests.
# By default, ESFS_TESTS_ENABLED is NOT defined, meaning ESFS's tests are disabled and compiled out. 

FILE(
	GLOB_RECURSE  
	esfs_test_src
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unitest/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unitest/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unitest/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/Test/linux/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/linux/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/linux/*.cpp"
	
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/src/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/src/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/extras/fixture/src/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/Test/Unity/extras/fixture/src/*.h"

	${PAL_TESTS_SOURCE_DIR}/TestRunner/pal_test${OS_BRAND}.c 
)

message ( "********************************************************************* ")
message ("esfs_test_src = [[${esfs_test_src}]]")
message ( "********************************************************************* ")

set (ESFS_TEST_FLAGS
    -DPAL_RUN_ALL_TESTS
)	

CREATE_TEST_LIBRARY(esfs_tests "${esfs_test_src}" "${ESFS_TEST_FLAGS}")
ADD_DEPENDENCIES(esfs_tests esfs platformCommon)

endif()
