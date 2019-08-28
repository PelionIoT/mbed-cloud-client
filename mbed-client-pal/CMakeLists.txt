INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING
cmake_minimum_required (VERSION 3.5)
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

if ((${OS_BRAND} MATCHES "Linux"))
    add_definitions(-DPAL_LINUX)
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
ADDSUBDIRS()
