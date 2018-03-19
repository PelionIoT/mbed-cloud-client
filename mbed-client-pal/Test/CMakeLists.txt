include_directories(../Source/PAL-Impl/Services-API) 
include_directories(../Source/Port/Platform-API)
option(SPLIT_BINARIES "Choose whether to split the tests into 2 binaries or not" OFF)





if (${OS_BRAND} MATCHES FreeRTOS)
	add_definitions(-DUNITY_OUTPUT_CHAR=unity_output_char)
endif()

add_definitions(-DSOTP_TESTING)

#on Linux, we might find different names for the network interface
#so we have to find it, and pass to the code.
if (${OS_BRAND} MATCHES Linux)
  add_definitions(-DPAL_NO_FATFS_SD_TEST=1)
  if (NOT USE_ETH_INTERFACE)
    execute_process(COMMAND ip -o -4 route show to default 
	                  COMMAND awk "{print $5}" 
			  COMMAND head -1 
	                  OUTPUT_STRIP_TRAILING_WHITESPACE
	                  OUTPUT_VARIABLE  ETHNAME)
    set(TMPD \"${ETHNAME}\")
    add_definitions(-DPAL_LINUX_ETH=${TMPD})
    message( "ETHNAME = ${ETHNAME}")
  else()
    add_definitions(-DPAL_LINUX_ETH=${USE_ETH_INTERFACE})
    message("Using ${USE_ETH_INTERFACE} for network")
  endif()
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
	add_definitions(-DDEBUG)
endif()

include_directories(Unitest)
include_directories(Common)  
include_directories(Unity/src) 
include_directories(Unity/extras/fixture/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/PAL_Modules/)


set (PAL_TESTS_SOURCE_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/PAL_Modules/)
set (PAL_TESTS_RUNNER_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/TESTS/Unitest/)
set (PAL_TESTS_SOTP_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/TESTS/Sotp/)
set (PAL_UNITY_SOURCE_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/Unity/src/)
set (PAL_UNITY_FIXTURE_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/Unity/extras/fixture/src)
set (PAL_TEST_BSP_DIR       ${CMAKE_CURRENT_SOURCE_DIR}/../Examples/PlatformBSP)
set (PAL_UTILS_DIR          ${CMAKE_CURRENT_SOURCE_DIR}/../Utils/memoryProfiler/Other)

  
file(GLOB PAL_TEST_RTOS_SRCS "${PAL_TESTS_SOURCE_DIR}/RTOS/*.c")

file(GLOB PAL_TEST_SANITY_SRCS "${PAL_TESTS_SOURCE_DIR}/Sanity/*.c")

file(GLOB PAL_TEST_NETWORK_SRCS "${PAL_TESTS_SOURCE_DIR}/Networking/*.c")

file(GLOB PAL_TEST_FS_SRCS "${PAL_TESTS_SOURCE_DIR}/FileSystem/*.c")

file(GLOB PAL_TEST_TLS_SRCS "${PAL_TESTS_SOURCE_DIR}/TLS/*.c")

file(GLOB_RECURSE PAL_TEST_CRYPTO_SRCS "${PAL_TESTS_SOURCE_DIR}/Crypto/*.c")

file(GLOB PAL_TEST_UPDATE_SRCS "${PAL_TESTS_SOURCE_DIR}/Update/*")

file(GLOB PAL_TEST_FLASH_SRCS "${PAL_TESTS_SOURCE_DIR}/Storage/*.c")

file(GLOB PAL_TEST_SOTP_SRCS "${PAL_TESTS_SOURCE_DIR}/SOTP/*.c")

file(GLOB PAL_TEST_MAIN_SRCS "${PAL_TESTS_SOURCE_DIR}/*.c")


file(GLOB PAL_TEST_RUNNER_SANITY_SRCS "${PAL_TESTS_RUNNER_DIR}/Sanity/*.c")

file(GLOB PAL_TEST_RUNNER_RTOS_SRCS "${PAL_TESTS_RUNNER_DIR}/RTOS/*.c")

file(GLOB PAL_TEST_RUNNER_NETWORK_SRCS "${PAL_TESTS_RUNNER_DIR}/Networking/*.c")

file(GLOB PAL_TEST_RUNNER_FS_SRCS "${PAL_TESTS_RUNNER_DIR}/FileSystem/*.c")

file(GLOB PAL_TEST_RUNNER_TLS_SRCS "${PAL_TESTS_RUNNER_DIR}/TLS/*.c")

file(GLOB PAL_TEST_RUNNER_CRYPTO_SRCS "${PAL_TESTS_RUNNER_DIR}/Crypto/*.c")

file(GLOB PAL_TEST_RUNNER_UPDATE_SRCS "${PAL_TESTS_RUNNER_DIR}/Update/*.c")

file(GLOB PAL_TEST_RUNNER_FLASH_SRCS "${PAL_TESTS_RUNNER_DIR}/Storage/*.c")

file(GLOB PAL_TEST_RUNNER_FULL_SRCS "${PAL_TESTS_RUNNER_DIR}/Full_pal/*.c")

file(GLOB PAL_TEST_RUNNER_SOTP_SRCS "${PAL_TESTS_SOTP_DIR}/security/*.c")


message(PAL_TESTS_RUNNER_DIR = ${PAL_TESTS_RUNNER_DIR})
message(PAL_TEST_MAIN_SRCS = ${PAL_TEST_MAIN_SRCS})


file(GLOB PAL_TEST_BSP_SRCS "${PAL_TEST_BSP_DIR}/${PAL_TARGET_DEVICE}_${OS_BRAND}/*")

set(PAL_TEST_UNITY_SRC
  	${PAL_UNITY_SOURCE_DIR}/unity.c
  	${PAL_UNITY_FIXTURE_DIR}/unity_fixture.c
)


set(PAL_INSECURE_ROT_SRC
	  ${PAL_TEST_BSP_DIR}/pal_insecure_ROT.c
	  )

if (PAL_MEMORY_STATISTICS) #currently working only in gcc based compilers
    list (APPEND PAL_TEST_BSP_SRCS  ${PAL_UTILS_DIR}/pal_memory.c)
    add_definitions(-DPAL_MEMORY_STATISTICS=1)
endif() 

ADD_GLOBALDIR(${PAL_TEST_BSP_DIR}/Include/)
ADD_GLOBALDIR(${PAL_TESTS_SOURCE_DIR}/Includes/)

set(test_src ${PAL_TEST_BSP_SRCS}; ${PAL_INSECURE_ROT_SRC}; ${PAL_TEST_SOTP_SRCS}; ${PAL_TEST_MAIN_SRCS}; ${PAL_TEST_NETWORK_SRCS}; ${PAL_TEST_TLS_SRCS}; ${PAL_TEST_CRYPTO_SRCS}; ${PAL_TEST_RTOS_SRCS}; ${PAL_TEST_FLASH_SRCS}; ${PAL_TEST_FS_SRCS}; ${PAL_TEST_UPDATE_SRCS}; ${PAL_TEST_SANITY_SRCS}; ${PAL_TEST_UNITY_SRC})
set (PAL_TEST_FLAGS
	-DPAL_TEST_RTOS
	-DPAL_TEST_FS
	-DPAL_TEST_UPDATE
	-DPAL_TEST_NETWORK
	-DPAL_TEST_TLS
	-DPAL_TEST_CRYPTO
	-DPAL_TEST_FLASH
)
	
set(sanity_test_src ${test_src}; ${PAL_TEST_RUNNER_SANITY_SRCS}) 

CREATE_TEST_LIBRARY(sanityTests "${sanity_test_src}" "${PAL_TEST_FLAGS}")	
	
set(rtos_test_src ${test_src}; ${PAL_TEST_RUNNER_RTOS_SRCS}) 

CREATE_TEST_LIBRARY(RTOSTests "${rtos_test_src}" "${PAL_TEST_FLAGS}")

set(network_test_src ${test_src}; ${PAL_TEST_RUNNER_NETWORK_SRCS}) 

CREATE_TEST_LIBRARY(NetworkTests "${network_test_src}" "${PAL_TEST_FLAGS}")

set(fs_test_src ${test_src}; ${PAL_TEST_RUNNER_FS_SRCS}) 

CREATE_TEST_LIBRARY(FileSystemTests "${fs_test_src}" "${PAL_TEST_FLAGS}")

set(tls_test_src ${test_src}; ${PAL_TEST_RUNNER_TLS_SRCS}) 

CREATE_TEST_LIBRARY(TLSTests "${tls_test_src}" "${PAL_TEST_FLAGS}")

set(crypto_test_src ${test_src}; ${PAL_TEST_RUNNER_CRYPTO_SRCS}) 

CREATE_TEST_LIBRARY(CryptoTests "${crypto_test_src}" "${PAL_TEST_FLAGS}")

set(update_test_src ${test_src}; ${PAL_TEST_RUNNER_UPDATE_SRCS}) 

CREATE_TEST_LIBRARY(UpdateTests "${update_test_src}" "${PAL_TEST_FLAGS}")

set(flash_test_src ${test_src}; ${PAL_TEST_RUNNER_FLASH_SRCS}) 

CREATE_TEST_LIBRARY(FlashTests "${flash_test_src}" "${PAL_TEST_FLAGS}")

set(sotp_test_src ${test_src}; ${PAL_TEST_RUNNER_SOTP_SRCS}) 

CREATE_TEST_LIBRARY(SotpTests "${sotp_test_src}" "${PAL_TEST_FLAGS}")

set(all_test_src ${test_src}; ${PAL_TEST_RUNNER_FULL_SRCS})

CREATE_TEST_LIBRARY(palTests "${all_test_src}" "${PAL_TEST_FLAGS}")


CREATE_LIBRARY(palBringup "${PAL_TEST_BSP_SRCS}" "")


