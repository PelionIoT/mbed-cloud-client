if(NOT YOTTA_TARGET)
    INCLUDE(CMakeForceCompiler)
    # CROSS COMPILER SETTING
    cmake_minimum_required (VERSION 2.8)
    SET(CMAKE_SYSTEM_NAME Generic)

    project(mbedPal)

    
    macro(SET_COMPILER_DBG_RLZ_FLAG flag value)
        SET(${flag}_DEBUG "${${flag}_DEBUG} ${value}")
        SET(${flag}_RELEASE "${${flag}_RELEASE} ${value}")
    #enable this if for debugging
    if (0)
     message("flag = ${flag}")
     message("value = ${value}")
     message("MY_C_FLAGS_RELEASE2 = ${CMAKE_C_FLAGS_RELEASE}")
    endif(0) # comment end
    endmacro(SET_COMPILER_DBG_RLZ_FLAG)

    if(DISALLOW_WARNINGS)
        if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
            SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-Werror")
            SET_COMPILER_DBG_RLZ_FLAG (CMAKE_CXX_FLAGS "-Werror")
        endif()
    endif()

    SET (PAL_VERSION ${PAL_VERSION_MAJOR}.${PAL_VERSION_MINOR}.${PAL_VERSION_PATCH})

    # configure a header file generator .in to pass some of the CMake settings
    # to the source code
    configure_file (
      "${PROJECT_SOURCE_DIR}/pal_version.h.in"
      "${PROJECT_BINARY_DIR}/pal_version.h"
      )
     
    if ((${OS_BRAND} MATCHES "Linux"))
        add_definitions(-DPAL_LINUX)
    endif() 

    if ((${OS_BRAND} MATCHES "AmigaOS"))
        add_definitions(-DPAL_AMIGAOS)
    endif() 

    MACRO(HEADER_DIRECTORIES return_list)
      FILE(GLOB_RECURSE new_list ${CMAKE_CURRENT_SOURCE_DIR}/Configs/pal_config/${OS_BRAND}/*.h)
      SET(dir_list "")
      FOREACH(file_path ${new_list})
          GET_FILENAME_COMPONENT(dir_path ${file_path} PATH)
          SET(dir_list ${dir_list} ${dir_path})
      ENDFOREACH()
      LIST(REMOVE_DUPLICATES dir_list)
      SET(${return_list} ${dir_list})
    ENDMACRO()

    set(config_list "")
    HEADER_DIRECTORIES(config_list)
    foreach(config_dir ${config_list})
      ADD_GLOBALDIR("${config_dir}")
    endforeach()
    
    ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/Configs/pal_config)

    # add the binary tree to the search path for include files
    # so that we will find TutorialConfig.h????????????????????????????????????????????????????????????????????????????
    ADDSUBDIRS() 
else()
    set(OS_BRAND "Linux")
    set(TLS_LIBRARY "mbedTLS")
    set(PAL_MODULE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Source)

    # find source files from the relavent directories
    set(PAL_IMPL_SOURCE_DIR ${PAL_MODULE_SOURCE_DIR}/PAL-Impl)
    set(PAL_PORT_SOURCE_DIR ${PAL_MODULE_SOURCE_DIR}/Port/Reference-Impl/OS_Specific/${OS_BRAND})
    set(PAL_TLS_SOURCE_DIR ${PAL_MODULE_SOURCE_DIR}/Port/Reference-Impl/Lib_Specific/${TLS_LIBRARY})
    set(PAL_EXAMPLE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Examples/PlatformBSP)

    file(GLOB_RECURSE PAL_SRCS "${PAL_IMPL_SOURCE_DIR}/*.c"
                               "${PAL_PORT_SOURCE_DIR}/Storage/FileSystem/*.c"
                               "${PAL_PORT_SOURCE_DIR}/Storage/Flash/*.c"
                               "${PAL_PORT_SOURCE_DIR}/Networking/*.c"
                               "${PAL_PORT_SOURCE_DIR}/RTOS/*.c"
                               "${PAL_PORT_SOURCE_DIR}/Update/*.c"
                               "${PAL_PORT_SOURCE_DIR}/Board_Specific/${PAL_TARGET_DEVICE}/*.c"
                               "${PAL_EXAMPLE_DIR}/pal_insecure_ROT.c"
                               "${PAL_TLS_SOURCE_DIR}/*.c")

    add_library(${YOTTA_MODULE_NAME} ${PAL_SRCS})

    # need to specify the yotta dependency here, otherwise yotta won't consider them when linking against this library
    target_link_libraries(${YOTTA_MODULE_NAME} mbedtls mbed-trace)

    # includes are taken care of via the module.json extraIncludes mechanism in order to be global
    # link libraries are handled by the module.josn dependencies mechanism
endif()
