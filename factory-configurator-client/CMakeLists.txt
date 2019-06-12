
cmake_minimum_required(VERSION 2.8)
project("fcc")

SET(MODULES
	ftcd-comm-base
	ftcd-comm-socket
	crypto-service
	factory-configurator-client
	logger
	utils
	mbed-trace-helper
	fcc-output-info-handler
)

# add fcc-bundle-handler only if secsrv-cbor repo exist
if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/secsrv-cbor)
      list (APPEND MODULES fcc-bundle-handler)
endif()

# includes
FOREACH(module ${MODULES})
	ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module})
ENDFOREACH()

# factory-configurator-client internal includes
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source/sotp)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/factory-configurator-client/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/logger/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/fcc-bundle-handler/source/include)

# esfs
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/mbed-client-esfs/source-pal/linux)

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

# fccstorage library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/storage/storage)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/storage/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/include)

FILE(GLOB FCC_STORAGE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_items_pal_sst.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_items_pelion_sst.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/key_slot_allocator.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_dispatcher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_common.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_psa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/storage/source/storage_non_psa.c"
)

# fccstorage is depending sotp and esfs.
add_library(fccstorage STATIC "${FCC_STORAGE_SRC}")
add_dependencies(fccstorage esfs sotp)
target_link_libraries(fccstorage esfs sotp)

# crypto service library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/crypto-service)
FILE(GLOB CRYPTO_SERVICE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/source/*.c"
)
add_library(crypto-service STATIC "${CRYPTO_SERVICE_SRC}")
#add_dependencies(crypto-service pal)
#target_link_libraries(crypto-service pal)

# key-config-manager library
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/key-config-manager)
FILE(GLOB KEY_CONFIG_MANAGER_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/key_config_manager.c"
)

# fccstorage is depending sotp and esfs.
add_library(key-config-manager STATIC "${KEY_CONFIG_MANAGER_SRC}")
add_dependencies(key-config-manager crypto-service fccstorage)
target_link_libraries(key-config-manager crypto-service fccstorage)


CREATE_LIBRARY(factory-configurator-client "${factory-configurator-client}" "")

# Create buld dependencies to ensure all the needed parts get build
add_dependencies(factory-configurator-client fccstorage key-config-manager pal)

# Add linking dependency for all the subcomponents of mbedCloudClient. This allows one to
# just have "target_link_libraries(<client-application> mbedCloudClient)" and cmake will
# automatically build all the submodules.
target_link_libraries(factory-configurator-client fccstorage key-config-manager fccstorage pal)


ADDSUBDIRS()
