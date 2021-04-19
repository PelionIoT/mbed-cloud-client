if(CONFIG_PELION_SOURCES)

  message(STATUS "Building Pelion Device Management Client Library")

  include(macros.cmake)

  if(NOT "${CONFIG_PELION_MBEDTLS_LIB_NAME}" STREQUAL "mbedTLS")
    zephyr_interface_library_named(mbedTLS)
    separate_arguments(LIB_LIST UNIX_COMMAND ${CONFIG_PELION_MBEDTLS_LIB_NAME})
    foreach(lib ${LIB_LIST})
      zephyr_link_libraries(${lib} -lc)
      target_link_libraries(mbedTLS INTERFACE ${lib})
    endforeach()
  endif()

  # Pelion configuration
  SET(OS_BRAND ZephyrOS)
  SET(MBED_CLOUD_CLIENT_DEVICE Generic)
  SET(DISABLE_PAL_TESTS foo)
  SET(TLS_LIBRARY mbedTLS)
  SET(STORAGE_KVSTORE 1)

  SET(PELION_CLIENT_DEFINITIONS
    -DMBED_CLOUD_CLIENT_ENDPOINT_TYPE="${CONFIG_PELION_ENDPOINT_TYPE}"
    -DMBED_CLOUD_CLIENT_LIFETIME=${CONFIG_PELION_LIFETIME}
    -DMBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=${CONFIG_PELION_EVENT_LOOP_THREAD_STACK_SIZE}
    -DSN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE=${CONFIG_PELION_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE}
    -DMBED_CONF_MBED_TRACE_ENABLE=$<BOOL:${CONFIG_PELION_DEBUG_TRACE}>
    -DPAL_SUPPORT_NAT64=$<BOOL:${CONFIG_PELION_PAL_SUPPORT_NAT64}>

    -DPAL_PLATFORM_DEFINED_CONFIGURATION="zephyr_default.h"
    -DMBED_CONF_STORAGE_STORAGE_TYPE=TDB_INTERNAL
    -DMBED_CONF_STORAGE_TDB_INTERNAL_INTERNAL_BASE_ADDRESS=0x0
    -DMBED_CONF_STORAGE_TDB_INTERNAL_INTERNAL_SIZE=0x6000
    -DMBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT=1
    -DCOMPONENT_FLASHIAP=1
    -DFLASHIAP_APP_ROM_END_ADDR=0x0
  )

  if(${CONFIG_PELION_TRANSPORT_MODE_TCP})
    SET(PELION_CLIENT_DEFINITIONS ${PELION_CLIENT_DEFINITIONS} -DMBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP=1)
  endif()

  if(${CONFIG_PELION_TRANSPORT_MODE_UDP})
    SET(PELION_CLIENT_DEFINITIONS ${PELION_CLIENT_DEFINITIONS} -DMBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP=1)
  endif()

  if(${CONFIG_PELION_TRANSPORT_MODE_UDP_QUEUE})
    SET(PELION_CLIENT_DEFINITIONS ${PELION_CLIENT_DEFINITIONS} -DMBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE=1)
  endif()

  if(${CONFIG_PELION_UPDATE})
    SET(PELION_CLIENT_DEFINITIONS ${PELION_CLIENT_DEFINITIONS}
      -DMBED_CLOUD_CLIENT_SUPPORT_UPDATE=1
      -DMBED_CLOUD_CLIENT_UPDATE_BUFFER=${CONFIG_PELION_UPDATE_BUFFER}
      -DMBED_CONF_UPDATE_CLIENT_MCUBOOT_DEFAULT_PERMANENT=$<BOOL:${CONFIG_PELION_UPDATE_PERMANENT}>
      -DMBED_CONF_UPDATE_CLIENT_STORAGE_PAGE=${CONFIG_PELION_UPDATE_PAGE_SIZE}
      -DMBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL=MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP
      -DMBED_CLOUD_CLIENT_UPDATE_STORAGE=ARM_UCP_FLASHIAP_MCUBOOT
      -DARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT=1
      -DARM_UC_PROFILE_MBED_CLOUD_CLIENT=1
      -DATOMIC_QUEUE_USE_PAL=1
      -DAPPLICATION_ADDR=0x0
      -DMBED_CLOUD_CLIENT_USER_CONFIG_FILE="zephyr_update.h"
    )

    if(${CONFIG_PELION_UPDATE_DEVELOPER})
      SET(PELION_CLIENT_DEFINITIONS ${PELION_CLIENT_DEFINITIONS}
        -DMBED_CLOUD_DEV_UPDATE_CERT=1
        -DMBED_CLOUD_DEV_UPDATE_ID=1
      )
    endif()
  endif()

  add_definitions(${PELION_CLIENT_DEFINITIONS})

  include_directories(../pal_config)

  # Zephyr compile options
  include_directories($<TARGET_PROPERTY:zephyr_interface,INTERFACE_INCLUDE_DIRECTORIES>)
  include_directories($<TARGET_PROPERTY:zephyr_interface,INTERFACE_SYSTEM_INCLUDE_DIRECTORIES>)
  add_compile_definitions($<TARGET_PROPERTY:zephyr_interface,INTERFACE_COMPILE_DEFINITIONS>)
  add_compile_options($<TARGET_PROPERTY:zephyr_interface,INTERFACE_COMPILE_OPTIONS>)

  # Add include directories of Zephyr's implemented POSIX API headers.
  include_directories($<TARGET_PROPERTY:posix_subsys,INTERFACE_INCLUDE_DIRECTORIES>)

  # Stub libraries
  add_library(platformCommon INTERFACE)
  add_library(mbedcrypto INTERFACE)
  add_library(mbedx509 INTERFACE)

  if(EXISTS ${ZEPHYR_PELION_DM_MODULE_DIR})
    message(STATUS "Using ZEPHYR_PELION_DM_MODULE_DIR ${ZEPHYR_PELION_DM_MODULE_DIR}")
    set(PELION_LIBRARY_DIR ${ZEPHYR_PELION_DM_MODULE_DIR})
  elseif(EXISTS ${ZEPHYR_PELION-DM_MODULE_DIR})
    message(STATUS "Using ZEPHYR_PELION-DM_MODULE_DIR ${ZEPHYR_PELION-DM_MODULE_DIR}")
    set(PELION_LIBRARY_DIR ${ZEPHYR_PELION-DM_MODULE_DIR})
  else()
    message(FATAL_ERROR "ZEPHYR_PELION_DM_MODULE_DIR or ZEPHYR_PELION-DM_MODULE_DIR not defined")
  endif()

  # Add Pelion's root CMakeListst.txt
  add_subdirectory(${PELION_LIBRARY_DIR} pelion)

  zephyr_get_targets(${PELION_LIBRARY_DIR} "STATIC_LIBRARY;OBJECT_LIBRARY" ALL_TARGETS)
  foreach(target ${ALL_TARGETS})
    # Don't build all libraries by default.
    # Only libraries that are linked into Zephyr will be built due to dependencies.
    set_property(TARGET ${target} PROPERTY EXCLUDE_FROM_ALL TRUE)

    # Make sure that generated header is available when building client targets.
    add_dependencies(${target} ${SYSCALL_LIST_H_TARGET})
  endforeach()

  # Include Pelion headers
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/certificate-enrollment-client/certificate-enrollment-client)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/factory-configurator-client/key-config-manager/key-config-manager)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/factory-configurator-client/factory-configurator-client/factory-configurator-client)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/factory-configurator-client/mbed-trace-helper/mbed-trace-helper)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/global_api)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/include)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/kv_map)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/helpers)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/conf)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/kvstore/tdbstore)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-client)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-client/mbed-client)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-client/mbed-client-c)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-client-pal/Source)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-client-pal/Source/PAL-Impl/Services-API)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-cloud-client)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-coap/mbed-coap)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/mbed-trace)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/nanostack-libservice/mbed-client-libservice)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/sal-stack-nanostack-eventloop/nanostack-event-loop)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/source)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/update-client-hub)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/update-client-hub/modules/common)
  zephyr_system_include_directories(${PELION_LIBRARY_DIR}/zephyr/config)

  if (CONFIG_APP_LINK_WITH_PELION_CLIENT)
    # Linking with lc, lgcc, and lstdc++ to make sure the linking comes in the right order.
    # Kernel target is explicitly given for kernel function visibility.
    # The linking to TARGET_FILE is used to avoid creating circular dependencies by bringing in all kernel options.
    zephyr_link_libraries(mbedCloudClient $<TARGET_FILE:kernel> -lc -lgcc -lstdc++)

    # Add Zephyr interface library to be able to link with library with Zephyr's APP_LINK_WITH_
    zephyr_interface_library_named(pelion_client)
    target_link_libraries(pelion_client INTERFACE mbedCloudClient)

    # Make sure the application sees the Pelion definitions
    target_compile_definitions(pelion_client INTERFACE ${PELION_CLIENT_DEFINITIONS})
  endif()

endif()
