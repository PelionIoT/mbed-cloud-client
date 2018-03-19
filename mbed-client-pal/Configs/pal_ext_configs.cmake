SET(PAL_BSP_DIR ${NEW_CMAKE_SOURCE_DIR}/mbed-client-pal/Configs/)
SET(PAL_TLS_BSP_DIR ${PAL_BSP_DIR}/${TLS_LIBRARY})
SET(PAL_PLATFORM_BSP_DIR ${PAL_BSP_DIR}/pal_config)

#choose the samll test suit of esfs - becasue the latge one does not fit with networking to image size
add_definitions(-DESFS_INTERACTIVE_TEST)
add_definitions(-DSOTP_LOG=0)

if (${TLS_LIBRARY} MATCHES mbedTLS)
	# PAL specific configurations for mbedTLS
    if (NOT (${OS_BRAND} MATCHES "FreeRTOS"))
	    add_definitions(-DMBEDTLS_CONFIG_FILE="\\"${PAL_TLS_BSP_DIR}/mbedTLSConfig_${OS_BRAND}.h"\\")
    else()
        add_definitions(-DMBEDTLS_CONFIG_FILE=\"${PAL_TLS_BSP_DIR}/mbedTLSConfig_${OS_BRAND}.h\")
    endif()
    message("PAL_TLS_BSP_DIR ${PAL_TLS_BSP_DIR}/pal_${OS_BRAND}.h")
endif()



