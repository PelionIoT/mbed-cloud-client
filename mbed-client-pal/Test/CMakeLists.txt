
if(DEFINED DISABLE_PAL_TESTS)
    # disabled and compiled out tests if DISABLE_PAL_TESTS variable is defined
  return()
endif()

include_directories(../Source/PAL-Impl/Services-API)
include_directories(../Source/Port/Platform-API)
option(SPLIT_BINARIES "Choose whether to split the tests into 2 binaries or not" OFF)

if (${OS_BRAND} MATCHES FreeRTOS)
    # XXX: the old version redirected UNITY_OUTPUT_CHAR() to unity_output_char(),
    # which redirected the call to PUTCHAR() which was defined in
    # K64F_FreeRTOS/K64F_FreeRTOS/Device/MK64F/utilities/fsl_debug_console.h
    # and which redirected call to putchar() or DbgConsole_Putchar().
    # The console works just fine without this so lets leave it out as no
    # platform specific file defines it anymore.
    # add_definitions(-DUNITY_OUTPUT_CHAR=unity_output_char)
endif()

add_definitions(-DRBP_TESTING)

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


file(GLOB CLOUD_CREDENTIALS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed_cloud_dev_credentials.c")

file(GLOB PAL_TEST_RTOS_SRCS "${PAL_TESTS_SOURCE_DIR}/RTOS/*.c")

file(GLOB PAL_TEST_ROT_SRCS "${PAL_TESTS_SOURCE_DIR}/ROT/*.c")

file(GLOB PAL_TEST_ENTROPY_SRCS "${PAL_TESTS_SOURCE_DIR}/Entropy/*.c")

file(GLOB PAL_TEST_SANITY_SRCS "${PAL_TESTS_SOURCE_DIR}/Sanity/*.c")

file(GLOB PAL_TEST_NETWORK_SRCS "${PAL_TESTS_SOURCE_DIR}/Networking/*.c")

file(GLOB PAL_TEST_FS_SRCS "${PAL_TESTS_SOURCE_DIR}/FileSystem/*.c")

file(GLOB PAL_TEST_TIME_SRCS "${PAL_TESTS_SOURCE_DIR}/Time/*.c")

file(GLOB PAL_TEST_TLS_SRCS "${PAL_TESTS_SOURCE_DIR}/TLS/*.c")

file(GLOB PAL_TEST_DRBG_SRCS "${PAL_TESTS_SOURCE_DIR}/DRBG/*")

file(GLOB PAL_TEST_UPDATE_SRCS "${PAL_TESTS_SOURCE_DIR}/Update/*")

file(GLOB PAL_TEST_FLASH_SRCS "${PAL_TESTS_SOURCE_DIR}/Storage/*.c")

file(GLOB PAL_TEST_SOTP_SRCS "${PAL_TESTS_SOURCE_DIR}/SOTP/*.c")

file(GLOB PAL_TEST_MAIN_SRCS "${PAL_TESTS_SOURCE_DIR}/*.c")


file(GLOB PAL_TEST_RUNNER_SANITY_SRCS "${PAL_TESTS_RUNNER_DIR}/Sanity/*.c")

file(GLOB PAL_TEST_RUNNER_RTOS_SRCS "${PAL_TESTS_RUNNER_DIR}/RTOS/*.c")

file(GLOB PAL_TEST_RUNNER_ROT_SRCS "${PAL_TESTS_RUNNER_DIR}/ROT/*.c")

file(GLOB PAL_TEST_RUNNER_ENTROPY_SRCS "${PAL_TESTS_RUNNER_DIR}/Entropy/*.c")

file(GLOB PAL_TEST_RUNNER_NETWORK_SRCS "${PAL_TESTS_RUNNER_DIR}/Networking/*.c")

file(GLOB PAL_TEST_RUNNER_FS_SRCS "${PAL_TESTS_RUNNER_DIR}/FileSystem/*.c")

file(GLOB PAL_TEST_RUNNER_TIME_SRCS "${PAL_TESTS_RUNNER_DIR}/Time/*.c")

file(GLOB PAL_TEST_RUNNER_TLS_SRCS "${PAL_TESTS_RUNNER_DIR}/TLS/*.c")

file(GLOB PAL_TEST_RUNNER_DRBG_SRCS "${PAL_TESTS_RUNNER_DIR}/DRBG/*.c")

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

# shared source which is built to all test libraries
set(test_src ${PAL_TEST_MAIN_SRCS})

set (PAL_TEST_FLAGS
    -DPAL_TEST_RTOS
    -DPAL_TEST_ROT
    -DPAL_TEST_ENTROPY
    -DPAL_TEST_DRBG
    -DPAL_TEST_FS
    -DPAL_TEST_UPDATE
    -DPAL_TEST_NETWORK
    -DPAL_TEST_TLS
    -DPAL_TEST_TIME
    -DPAL_TEST_FLASH
)

# Compile the PAL's fork of unity into libpalunity, so it can be compiled once
# and shared with all the separate test runners
# Note: this is not using the CREATE_LIBRARY() on purpose, as it would pollute all the
# executables with the library.
add_library(palunity STATIC ${PAL_TEST_UNITY_SRC})
target_compile_definitions(palunity PRIVATE ${PAL_TEST_FLAGS})

# link each test with the pal library, so it will get built as a dependency.

# Each module's test code (and its runner) is now built into its own library.
# Having them separate is convenient to reduce build times and especially handy
# when one needs to debug something, as test executable is not running or building
# unnecessary code.

set(sanity_test_src ${test_src}; ${PAL_TEST_RUNNER_SANITY_SRCS}; ${PAL_TEST_SANITY_SRCS})
CREATE_TEST_LIBRARY(sanityTests "${sanity_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(sanityTests pal palunity platformCommon)
target_link_libraries(sanityTests pal palunity platformCommon)

set(rtos_test_src ${test_src}; ${PAL_TEST_RUNNER_RTOS_SRCS}; ${PAL_TEST_RTOS_SRCS})
CREATE_TEST_LIBRARY(RTOSTests "${rtos_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(RTOSTests pal palunity platformCommon)
target_link_libraries(RTOSTests pal palunity platformCommon)

set(rot_test_src ${test_src}; ${PAL_TEST_RUNNER_ROT_SRCS}; ${PAL_TEST_ROT_SRCS})
CREATE_TEST_LIBRARY(ROTTests "${rot_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(ROTTests pal palROT palunity platformCommon)
target_link_libraries(ROTTests pal palROT palunity platformCommon)

set(entropy_test_src ${test_src}; ${PAL_TEST_RUNNER_ENTROPY_SRCS}; ${PAL_TEST_ENTROPY_SRCS})
CREATE_TEST_LIBRARY(EntropyTests "${entropy_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(EntropyTests pal palunity platformCommon)
target_link_libraries(EntropyTests pal palunity platformCommon)

set(network_test_src ${test_src}; ${PAL_TEST_RUNNER_NETWORK_SRCS}; ${PAL_TEST_NETWORK_SRCS})
CREATE_TEST_LIBRARY(NetworkTests "${network_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(NetworkTests pal palunity platformCommon)
target_link_libraries(NetworkTests pal palunity platformCommon)

set(drbg_test_src ${test_src}; ${PAL_TEST_RUNNER_DRBG_SRCS}; ${PAL_TEST_DRBG_SRCS})
CREATE_TEST_LIBRARY(DRBGTests "${drbg_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(DRBGTests pal palunity platformCommon)
target_link_libraries(DRBGTests pal palunity platformCommon)

set(fs_test_src ${test_src}; ${PAL_TEST_RUNNER_FS_SRCS}; ${PAL_TEST_FS_SRCS})
CREATE_TEST_LIBRARY(FileSystemTests "${fs_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(FileSystemTests pal palunity platformCommon)
target_link_libraries(FileSystemTests pal palunity platformCommon)

set(time_test_src ${test_src}; ${PAL_TEST_RUNNER_TIME_SRCS}; ${PAL_TEST_TIME_SRCS})
CREATE_TEST_LIBRARY(TimeTests "${time_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(TimeTests pal palunity)
target_link_libraries(TimeTests pal palunity)

add_library(cloud_credentials STATIC ${CLOUD_CREDENTIALS_SRC})

set(tls_test_src ${test_src}; ${PAL_TEST_RUNNER_TLS_SRCS}; ${PAL_TEST_TLS_SRCS})
CREATE_TEST_LIBRARY(TLSTests "${tls_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(TLSTests pal palunity platformCommon cloud_credentials)
target_link_libraries(TLSTests pal palunity platformCommon cloud_credentials)

set(update_test_src ${test_src}; ${PAL_TEST_RUNNER_UPDATE_SRCS}; ${PAL_TEST_UPDATE_SRCS})
CREATE_TEST_LIBRARY(UpdateTests "${update_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(UpdateTests pal palunity platformCommon)
target_link_libraries(UpdateTests pal palunity platformCommon)

set(flash_test_src ${test_src}; ${PAL_TEST_RUNNER_FLASH_SRCS}; ${PAL_TEST_FLASH_SRCS})
CREATE_TEST_LIBRARY(FlashTests "${flash_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(FlashTests pal palunity platformCommon)
target_link_libraries(FlashTests pal palunity platformCommon)

set(sotp_test_src ${test_src}; ${PAL_TEST_RUNNER_SOTP_SRCS}; ${PAL_TEST_SOTP_SRCS})
CREATE_TEST_LIBRARY(SotpTests "${sotp_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(SotpTests pal palunity platformCommon)
target_link_libraries(SotpTests pal palunity platformCommon)

# this combines all the test libraries and calls all of their TEST_pal_<module>_GROUP_RUNNER
set(all_test_src ${test_src}; ${PAL_TEST_RUNNER_FULL_SRCS})
CREATE_TEST_LIBRARY(palTests "${all_test_src}" "${PAL_TEST_FLAGS}")
add_dependencies(palTests pal palunity sanityTests platformCommon)
target_link_libraries(palTests pal palunity platformCommon sanityTests RTOSTests ROTTests EntropyTests NetworkTests DRBGTests FileSystemTests TimeTests TLSTests UpdateTests FlashTests SotpTests)

