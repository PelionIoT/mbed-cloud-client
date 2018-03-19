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
