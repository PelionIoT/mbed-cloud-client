# ----------------------------------------------------------------------------
# Copyright 2017-2019 ARM Ltd.
#  
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  
#     http://www.apache.org/licenses/LICENSE-2.0
#  
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

cmake_minimum_required(VERSION 2.6)
project("sda")

SET(MODULES
	logger
	helpers
	mem
	platform
	sda-bundle-parser
	secure-device-access
	sda-cose
)

# includes
FOREACH(module ${MODULES})
	ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module})
ENDFOREACH()

# secure-device-access
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/secure-device-access/source/include)

SET(SOURCE_LIST "")

FOREACH(module ${MODULES})
	# sources
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/${module}/*.h")
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.c")
	LIST(APPEND SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/${module}/source/*.cpp")
ENDFOREACH()

FILE(GLOB secure-device-access-client ${SOURCE_LIST})

message ("*********************************************************************")
message ("secure-device-access-client = [[${secure-device-access-client}]]")
message ("*********************************************************************")

CREATE_LIBRARY(secure-device-access-client "${secure-device-access-client}" "")

ADDSUBDIRS()
