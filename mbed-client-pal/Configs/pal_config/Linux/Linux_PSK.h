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

#ifndef PAL_ENABLE_PSK
	#define PAL_ENABLE_PSK 1
#endif

#ifndef PAL_ENABLE_X509
	#define PAL_ENABLE_X509 0
#endif


#undef PAL_USE_SECURE_TIME
#define PAL_USE_SECURE_TIME 0


#define PAL_SKIP_TEST_MODULE_SOTP
#define PAL_SKIP_TEST_MODULE_RTOS
#define PAL_SKIP_TEST_MODULE_NETWORK
#define PAL_SKIP_TEST_MODULE_FILESYSTEM
#define PAL_SKIP_TEST_MODULE_UPDATE
#define PAL_SKIP_TEST_MODULE_INTERNALFLASH



#include "Linux_default.h"
