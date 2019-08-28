include_directories(Port/Platform-API)

# This is so other modules could include pal.h
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Services-API)

# Add the current the directory of this of this file as a global dir pal.h could include more qualified paths 
# and modules that use PAL could still include pal.h
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR})

set (PAL_MODULES_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Modules)
set (PAL_PORT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Port/Reference-Impl/OS_Specific/${OS_BRAND})
set (PAL_PORT_GENERIC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Port/Reference-Impl/Generic)

set(PAL_SRCS
    ${PAL_PORT_SOURCE_DIR}/Update/pal_plat_update.c

    ${PAL_MODULES_SOURCE_DIR}/Update/pal_update.c
    ${PAL_MODULES_SOURCE_DIR}/Storage/Flash/pal_internalFlash.c

    ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/pal_init.c 
)

if (NOT (${OS_BRAND} MATCHES "Linux"))
    set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_SOURCE_DIR}/Storage/Flash/pal_plat_internalFlash.c)
endif() 

set(PAL_RTOS_SRCS
    ${PAL_MODULES_SOURCE_DIR}/RTOS/pal_rtos.c
    ${PAL_PORT_SOURCE_DIR}/Board_Specific/TARGET_${MBED_CLOUD_CLIENT_DEVICE}/pal_plat_${MBED_CLOUD_CLIENT_DEVICE}.c
    ${PAL_PORT_SOURCE_DIR}/RTOS/pal_plat_rtos.c
)
if (${OS_BRAND} MATCHES "Linux")
    set(PAL_RTOS_SRCS ${PAL_RTOS_SRCS} ${PAL_PORT_SOURCE_DIR}/Board_Specific/pal_plat_linux_common.c)
endif() 

set(PAL_FILESYSTEM_SRCS
    ${PAL_MODULES_SOURCE_DIR}/Storage/FileSystem/pal_fileSystem.c
    ${PAL_PORT_SOURCE_DIR}/Storage/FileSystem/pal_plat_fileSystem.c
)

set(PAL_NETWORKING_SRCS
    ${PAL_MODULES_SOURCE_DIR}/Networking/pal_network.c
    ${PAL_PORT_SOURCE_DIR}/Networking/${NETWORK_STACK}/pal_plat_network.c
)

set(PAL_TLS_SRCS
    ${PAL_MODULES_SOURCE_DIR}/TLS/pal_TLS.c
    ${PAL_PORT_SOURCE_DIR}/../../Lib_Specific/${TLS_LIBRARY}/TLS/pal_plat_TLS.c
)

set(PAL_CRYPTO_SRCS
    ${PAL_MODULES_SOURCE_DIR}/Crypto/pal_Crypto.c
    ${PAL_PORT_SOURCE_DIR}/../../Lib_Specific/${TLS_LIBRARY}/Crypto/pal_plat_Crypto.c
)

set(PAL_DRBG_SRCS
    ${PAL_MODULES_SOURCE_DIR}/DRBG/pal_drbg.c
    # XXX: following file is in completely wrong place, it is tied to SOTP, not MBEDTLS
)

set(PAL_ROT_SRCS
    ${PAL_MODULES_SOURCE_DIR}/ROT/pal_rot.c
)

set(PAL_ENTROPY_SRCS
    ${PAL_MODULES_SOURCE_DIR}/Entropy/pal_entropy.c
)

set(PAL_TIME_SRCS
    ${PAL_MODULES_SOURCE_DIR}/Time/pal_time.c
)

# XXX: The mbedtls is configured as mbedTLS in PAL, which is not the correct name of the actual library.
# So we need to make it lowercase and add dependency using that.
string(TOLOWER ${TLS_LIBRARY} TLS_LINK_LIBRARY)


# TODO: conditionalize the next two additions with a option, but currently the SOTP is welded in tightly

# Add the time-module, which is generic enough to use on all platforms
set (PAL_TIME_SRCS ${PAL_TIME_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/Time/pal_plat_time.c)

# Add the platform dependent ROT implementation, which gets used if the PAL_USE_HW_ROT==1
set (PAL_ROT_SRCS ${PAL_ROT_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/ROT/External/pal_plat_rot_hw.c)
# Add the platform independent ROT implementation, which gets used if the PAL_USE_HW_ROT==0
set (PAL_ROT_SRCS ${PAL_ROT_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/ROT/SOTP/pal_plat_rot_sotp.c)

# Add the platform independent DRBG implementation
set (PAL_DRBG_SRCS ${PAL_DRBG_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/DRBG/SOTP/pal_plat_drbg_sotp.c)

# Add the platform independent entropy implementation
set (PAL_ENTROPY_SRCS ${PAL_ENTROPY_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/Entropy/pal_plat_entropy_sotp.c)

# Add the platform independent flash-over-filesystem implementation, which gets used if 
# PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM==1
set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/Storage/Flash/FlashOverFilesystem/pal_plat_internalFlash_FlashOverFilesystem.c)

# Add the platform independent noise implementation (used by the DRBG mdule)
set (PAL_DRBG_SRCS ${PAL_DRBG_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/DRBG/pal_plat_drbg_noise.c)

# Add PSA implementation for generating random buffer
set (PAL_DRBG_SRCS ${PAL_DRBG_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/DRBG/PSA/pal_plat_drbg_psa.c)

# Create the RTOS module library
add_library(palRTOS STATIC "${PAL_RTOS_SRCS}")

# Create the filesystem module library
add_library(palFilesystem STATIC "${PAL_FILESYSTEM_SRCS}")

# Create the Networking module library
add_library(palNetworking STATIC "${PAL_NETWORKING_SRCS}")

# Create the ROT module library
add_library(palROT STATIC "${PAL_ROT_SRCS}")

# Create the Entropy module library
add_library(palEntropy STATIC "${PAL_ENTROPY_SRCS}")


# Create the TLS module library
add_library(palTLS STATIC "${PAL_TLS_SRCS}")
add_dependencies(palTLS ${TLS_LINK_LIBRARY} palTime key-config-manager)
target_link_libraries(palTLS ${TLS_LINK_LIBRARY} palTime key-config-manager)

# Create the Crypto module library
add_library(palCrypto STATIC "${PAL_CRYPTO_SRCS}")
add_dependencies(palCrypto ${TLS_LINK_LIBRARY})
target_link_libraries(palCrypto ${TLS_LINK_LIBRARY})

# Create the DRBG module library
add_library(palDRBG STATIC "${PAL_DRBG_SRCS}")
add_dependencies(palDRBG palRTOS)
target_link_libraries(palDRBG palRTOS)


# Create the Time module library, add dependency to fcc (or storage inside it)
add_library(palTime STATIC "${PAL_TIME_SRCS}")
add_dependencies(palTime fccstorage)
target_link_libraries(palTime fccstorage)

# Create the main PAL library
add_library(pal STATIC "${PAL_SRCS}")


# Add dependency to SOTP and FCC so they will be built before and linked with PAL into final executable.
add_dependencies(pal palRTOS palFilesystem palNetworking palCrypto palDRBG palROT palEntropy sotp palTLS palTime)
target_link_libraries(pal palRTOS palFilesystem palNetworking palCrypto palDRBG palROT palEntropy sotp palTLS palTime)

# Bring in the ROT implementation from platform-common/application side. This can be
# empty also, selection is done based on PAL_USE_HW_ROT: if it is 0, then the pal_rot.c will need
# a pal_plat_osGetRoTFromHW() from this library.
if (PAL_USE_PLATFORM_ROT_OVERRIDE)
    # Use application-specific ROT implementation.
    add_dependencies(palROT platformROT)
    target_link_libraries(palROT platformROT)
else()
    # Use ROT implementation from platformCommonROT library.
    # XXX: This is now just a platform specific hack to keep builds running on Linux, where
    # code likely just uses the ROT-via-SOTP emulation, but the same mechanism really should
    # be used on all the platforms; the PAL side can not blindly reference to a external
    # function without specifying the dependency.
    if (${OS_BRAND} MATCHES "FreeRTOS")
        add_dependencies(palROT platformCommonROT)
        target_link_libraries(palROT platformCommonROT)
    endif()
endif()

# XXX: there is a ${PLATFORM_LIBS} in pal-tools, but nobody has set that on Linux
# and as the PAL really uses pthread in Linux, IMHO the dependency should be stated
# here too so it gets inherited to the call sites.
if (${OS_BRAND} MATCHES "Linux")
    target_link_libraries(pal pthread rt)
endif()

# On FreeRTOS also the PLATFORM_LIBS does not work properly (perhaps it should be removed/fixed on tools),
# as the libboard.a is not getting into correct linking order (libpal.a libboard.a) and the functions
# (eg. FLAHS_init()) from board are not found and linking fails on some executables (it works by luck on
# others). When the dependencies are set from PAL -> board specific libs, the cmake gets the order right.
if (${OS_BRAND} MATCHES "FreeRTOS")
    target_link_libraries(pal board)
endif()



