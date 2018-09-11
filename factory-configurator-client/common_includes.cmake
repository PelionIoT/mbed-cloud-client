

SET(MODULES
	ftcd-comm-base
	ftcd-comm-socket
	crypto-service		
	key-config-manager
	factory-configurator-client
	fcc-bundle-handler	
	secsrv-cbor
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
