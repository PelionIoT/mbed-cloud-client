include_directories(Port/Platform-API)
ADD_GLOBALDIR( ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Services-API)

set (PAL_MODULES_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/Modules)
set (PAL_PORT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Port/Reference-Impl/OS_Specific/${OS_BRAND})

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
    ${PAL_MODULES_SOURCE_DIR}/TLS/pal_TLS.c
    ${PAL_MODULES_SOURCE_DIR}/Crypto/pal_Crypto.c
    ${PAL_MODULES_SOURCE_DIR}/Update/pal_update.c
    ${PAL_MODULES_SOURCE_DIR}/Storage/FileSystem/pal_fileSystem.c
    ${PAL_MODULES_SOURCE_DIR}/Storage/Flash/pal_internalFlash.c

    ${CMAKE_CURRENT_SOURCE_DIR}/PAL-Impl/pal_init.c 
)

if ( NOT (${OS_BRAND} MATCHES "Linux"))        
       set (PAL_SRCS ${PAL_SRCS} ${PAL_PORT_SOURCE_DIR}/Storage/Flash/pal_plat_internalFlash.c)
endif() 

CREATE_LIBRARY(pal "${PAL_SRCS}" "")

# XXX: The mbedtls is configured as mbedTLS in PAL, which is not the correct name of the actual library.
# So we need to make it lowercase and add dependency using that.
string(TOLOWER ${TLS_LIBRARY} TLS_LINK_LIBRARY)

# PAL is tightly coupled with SOTP, which is packaged to esfs -library. So add the dependency
# so it will be build before and linked with PAL into final executable.
add_dependencies(pal ${TLS_LINK_LIBRARY} esfs mbedTrace)
target_link_libraries(pal ${TLS_LINK_LIBRARY} esfs mbedTrace)

# XXX: there is a ${PLATFORM_LIBS} in pal-tools, but nobody has set that on Linux
# and as the PAL really uses pthread in Linux, IMHO the dependency should be stated
# here too so it gets inherited to the call sites.
if (${OS_BRAND} MATCHES "Linux")
    target_link_libraries(pal pthread rt)
endif()

