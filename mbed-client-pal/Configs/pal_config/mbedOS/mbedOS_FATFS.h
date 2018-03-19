/*******************************************************************************
* Copyright 2016, 2017 ARM Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef PAL_MBEDOS_CONFIGURATION_H_

#include "cmsis_os.h"

/*!
* \brief This file is for more specific definitions (per board, if needed).
*        if this file is defined it will be included from pal_configuration.h
*        if not, the default file will be included - if needed
*/
#include "mbedOS_default.h"

#define PAL_SKIP_TEST_MODULE_RTOS
#define PAL_SKIP_TEST_MODULE_NETWORK
#define PAL_SKIP_TEST_MODULE_CRYPTO
#define PAL_SKIP_TEST_MODULE_UPDATE
#define PAL_SKIP_TEST_MODULE_TLS
#define PAL_SKIP_TEST_MODULE_INTERNALFLASH

#endif /* PAL_MBEDOS_CONFIGURATION_H_ */
