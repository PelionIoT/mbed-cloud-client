
cmake_minimum_required(VERSION 2.8)
project("fcc")

SET(MODULES
    ftcd-comm-base
    ftcd-comm-socket
    factory-configurator-client
    logger
    utils
    mbed-trace-helper
    fcc-output-info-handler
    fcc-bundle-handler
)

# includes
FOREACH(module ${MODULES})
    ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module})
ENDFOREACH()

# factory-configurator-client internal includes
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/factory-configurator-client/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/logger/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/fcc-bundle-handler/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/storage/source/include)

# esfs, sotp
if(NOT LINK_WITH_TRUSTED_STORAGE)
    ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source/include)
    ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source/sotp)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/api)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux)
endif()

SET(SOURCE_LIST "")

FOREACH(module ${MODULES})
    # sources
    LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module}/*.h")
    LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.c")
    LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.cpp")
ENDFOREACH()

FILE(GLOB factory-configurator-client ${SOURCE_LIST})

message("*********************************************************************")
message("factory-configurator-client = [[${factory-configurator-client}]]")
message("*********************************************************************")

# crypto service library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/crypto-service)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/source/include)
FILE(GLOB CRYPTO_SERVICE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/source/*.c"
)
add_library(crypto-service STATIC "${CRYPTO_SERVICE_SRC}")
add_dependencies(crypto-service palDRBG ssl-platform)
target_link_libraries(crypto-service palDRBG ssl-platform)


# fccstorage library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/storage/storage)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/storage/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/psa-driver)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source/include)

FILE(GLOB FCC_STORAGE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/pal_plat_sst_impl.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_pal_sst.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_pelion_sst.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_common.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_psa.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_non_psa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/key_slot_allocator.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source/psa_driver_common.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source/psa_driver_crypto.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source/psa_driver_dispatcher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa-driver/source/psa_driver_ps.c"

if(PARSEC_TPM_SE_SUPPORT)
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/se_slot_manager.c"
endif()

)

if(PARSEC_TPM_SE_SUPPORT)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../pal-platform/Middleware/parsec_se_driver/parsec_se_driver/include)
endif()

add_library(fccstorage STATIC "${FCC_STORAGE_SRC}")
if(LINK_WITH_TRUSTED_STORAGE)
    add_dependencies(fccstorage crypto-service trusted_storage)
    target_link_libraries(fccstorage crypto-service trusted_storage key-config-manager)
endif()
if(STORAGE_KVSTORE)
    add_dependencies(fccstorage crypto-service kvstore)
    target_link_libraries(fccstorage crypto-service kvstore)
endif()
if(STORAGE_ESFS)
    add_dependencies(fccstorage crypto-service esfs sotp)
    target_link_libraries(fccstorage crypto-service esfs sotp)
endif()
if(NOT (${OS_BRAND} MATCHES "Linux"))
# Add the KVStore based storage implementation, which gets used if
# MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is defined
    add_dependencies(fccstorage crypto-service kvstore)
    target_link_libraries(fccstorage crypto-service kvstore)
else()
    # For backwards compatibility with ESFS (Linux)
    add_dependencies(fccstorage crypto-service esfs sotp)
    target_link_libraries(fccstorage crypto-service esfs sotp)
endif()

if(PARSEC_TPM_SE_SUPPORT)
    # involve parsec se driver cmake to the build
    # Decided to use "UNKNOWN" type of imported library, that causes cmake to link with the library as is.
    add_library(parsec_driver UNKNOWN IMPORTED)

    set_property(TARGET parsec_driver PROPERTY IMPORTED_LOCATION_DEBUG
        "${CMAKE_CURRENT_SOURCE_DIR}/../../pal-platform/Middleware/parsec_se_driver/parsec_se_driver/target/debug/libparsec_se_driver.a")

    set_property(TARGET parsec_driver PROPERTY IMPORTED_LOCATION_RELEASE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../pal-platform/Middleware/parsec_se_driver/parsec_se_driver/target/release/libparsec_se_driver.a")

    target_link_libraries(fccstorage parsec_driver -ldl)
endif()

# key-config-manager library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/key-config-manager)
FILE(GLOB KEY_CONFIG_MANAGER_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/key_config_manager.c"
)

# fccstorage is depending sotp and esfs.
add_library(key-config-manager STATIC "${KEY_CONFIG_MANAGER_SRC}")
add_dependencies(key-config-manager fccstorage)
target_link_libraries(key-config-manager fccstorage)

CREATE_LIBRARY(factory-configurator-client "${factory-configurator-client}" "")

# Create buld dependencies to ensure all the needed parts get build
add_dependencies(factory-configurator-client fccstorage key-config-manager pal tinycbor)

# Add linking dependency for all the subcomponents of mbedCloudClient. This allows one to
# just have "target_link_libraries(<client-application> mbedCloudClient)" and cmake will
# automatically build all the submodules.
target_link_libraries(factory-configurator-client fccstorage key-config-manager pal tinycbor)

if (${OS_BRAND} MATCHES "Zephyr")
    target_link_libraries(crypto-service PUBLIC ${TLS_LIBRARY})
endif()

ADDSUBDIRS()
