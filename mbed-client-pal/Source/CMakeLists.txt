include_directories(Port/Platform-API)
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Services-API)

set (PAL_MODULES_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Modules)
set (PAL_PORT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Port/Reference-Impl/OS_Specific/${OS_BRAND})
set (PAL_PORT_GENERIC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Port/Reference-Impl/Generic)

set(PAL_SRCS
    ${PAL_PORT_SOURCE_DIR}/Networking/${NETWORK_STACK}/pal_plat_network.c
    ${PAL_PORT_SOURCE_DIR}/RTOS/pal_plat_rtos.c
    ${PAL_PORT_SOURCE_DIR}/../../Lib_Specific/${TLS_LIBRARY}/TLS/pal_plat_TLS.c
    ${PAL_PORT_SOURCE_DIR}/../../Lib_Specific/${TLS_LIBRARY}/Crypto/pal_plat_Crypto.c
    ${PAL_PORT_SOURCE_DIR}/Update/pal_plat_update.c
    ${PAL_PORT_SOURCE_DIR}/Storage/FileSystem/pal_plat_fileSystem.c    
    ${PAL_PORT_SOURCE_DIR}/Board_Specific/TARGET_${MBED_CLOUD_CLIENT_DEVICE}/pal_plat_${MBED_CLOUD_CLIENT_DEVICE}.c        

    ${PAL_MODULES_SOURCE_DIR}/Networking/pal_network.c
    ${PAL_MODULES_SOURCE_DIR}/RTOS/pal_rtos.c
    ${PAL_MODULES_SOURCE_DIR}/ROT/pal_rot.c
    ${PAL_MODULES_SOURCE_DIR}/Time/pal_time.c
    ${PAL_MODULES_SOURCE_DIR}/TLS/pal_TLS.c
    ${PAL_MODULES_SOURCE_DIR}/Crypto/pal_Crypto.c
    ${PAL_MODULES_SOURCE_DIR}/DRBG/pal_drbg.c
    ${PAL_MODULES_SOURCE_DIR}/Update/pal_update.c
    ${PAL_MODULES_SOURCE_DIR}/Storage/FileSystem/pal_fileSystem.c
    ${PAL_MODULES_SOURCE_DIR}/Storage/Flash/pal_internalFlash.c

    ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/pal_init.c 
)

if ( NOT (${OS_BRAND} MATCHES "Linux") AND NOT (${OS_BRAND} MATCHES "AmigaOS"))        
       set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_SOURCE_DIR}/Storage/Flash/pal_plat_internalFlash.c)
endif() 

if (${OS_BRAND} MATCHES "AmigaOS")
    set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_SOURCE_DIR}/RTOS/semaphore.c)
endif()

# TODO: conditionalize the next two additions with a option, but currently the SOTP is welded in tightly

# Add the time-module, which is generic enough to use on all platforms which just have the
# SOTP available. 
set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/Time/SOTP/pal_plat_time_sotp.c)

# Add the platform dependent ROT implementation, which gets used if the PAL_USE_HW_ROT==1
set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/ROT/External/pal_plat_rot_hw.c)
# Add the platform independent ROT implementation, which gets used if the PAL_USE_HW_ROT==0
set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/ROT/SOTP/pal_plat_rot_sotp.c)

# Add the platform independent DRBG implementation
set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_GENERIC_SOURCE_DIR}/DRBG/SOTP/pal_plat_drbg_sotp.c)


# Create the main PAL library
CREATE_LIBRARY(pal "${PAL_SRCS}" "")

# XXX: The mbedtls is configured as mbedTLS in PAL, which is not the correct name of the actual library.
# So we need to make it lowercase and add dependency using that.
string(TOLOWER ${TLS_LIBRARY} TLS_LINK_LIBRARY)

# Add dependency to SOTP so it will be build before and linked with PAL into final executable.
add_dependencies(pal ${TLS_LINK_LIBRARY} sotp)
target_link_libraries(pal ${TLS_LINK_LIBRARY} sotp)

# Bring in the ROT implementation from platform-common/application side. This can be
# empty also, selection is done based on PAL_USE_HW_ROT: if it is 0, then the pal_rot.c will need
# a pal_plat_osGetRoTFromHW() from this library.
if (PAL_USE_PLATFORM_ROT_OVERRIDE)
    # Use application-specific ROT implementation.
    add_dependencies(pal platformROT)
    target_link_libraries(pal platformROT)
else()
    # Use ROT implementation from platformCommonROT library.
    # XXX: This is now just a platform specific hack to keep builds running on Linux, where
    # code likely just uses the ROT-via-SOTP emulation, but the same mechanism really should
    # be used on all the platforms; the PAL side can not blindly reference to a external
    # function without specifying the dependency.
    if (${OS_BRAND} MATCHES "FreeRTOS")
        add_dependencies(pal platformCommonROT)
        target_link_libraries(pal platformCommonROT)
    endif()
endif()

# XXX: there is a ${PLATFORM_LIBS} in pal-tools, but nobody has set that on Linux
# and as the PAL really uses pthread in Linux, IMHO the dependency should be stated
# here too so it gets inherited to the call sites.
if (${OS_BRAND} MATCHES "Linux")
    target_link_libraries(pal pthread rt)
endif()

if (${OS_BRAND} MATCHES "AmigaOS")
    target_link_libraries(pal atomic net)
endif()

# On FreeRTOS also the PLATFORM_LIBS does not work properly (perhaps it should be removed/fixed on tools),
# as the libboard.a is not getting into correct linking order (libpal.a libboard.a) and the functions
# (eg. FLAHS_init()) from board are not found and linking fails on some executables (it works by luck on
# others). When the dependencies are set from PAL -> board specific libs, the cmake gets the order right.
if (${OS_BRAND} MATCHES "FreeRTOS")
    target_link_libraries(pal board)
endif()


