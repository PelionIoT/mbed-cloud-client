
cmake_minimum_required(VERSION 2.8)
project("fcc")

SET(MODULES
	ftcd-comm-base
	ftcd-comm-socket
	crypto-service		
	key-config-manager
	factory-configurator-client
	fcc-bundle-handler	
	logger
	storage
	utils
	mbed-trace-helper
	fcc-output-info-handler
)

# includes
FOREACH(module ${MODULES})
	ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module})
ENDFOREACH()

# factory-configurator-client internal includes
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/crypto-service/source/include)
ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/key-config-manager/source/include)
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

CREATE_LIBRARY(factory-configurator-client "${factory-configurator-client}" "")

ADDSUBDIRS()
