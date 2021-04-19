if (NOT (${OS_BRAND} MATCHES "Linux"))
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/helpers)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/conf)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/kv_map)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/global_api)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/tdbstore)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/securestore)

SET(KVSTORE_SRCS
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/FlashIAPBlockDevice.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/tdbstore/TDBStore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/BufferedBlockDevice.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/global_api/kvstore_global_api.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/kv_map/KVMap.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/conf/kv_config.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/pal_plat_rot.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/DeviceKey.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/FlashSimBlockDevice.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/SlicingBlockDevice.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/securestore/SecureStore.cpp
)
add_library(kvstore STATIC "${KVSTORE_SRCS}")
if (${OS_BRAND} MATCHES "Zephyr")
        target_link_libraries(kvstore PUBLIC ${TLS_LIBRARY})
endif()

endif()

