// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#ifndef __PSA_DRIVER_SE_H__
#define __PSA_DRIVER_SE_H__


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_ATCA_SUPPORT
#include "atecc608a_se.h"
#define PSA_DRIVER_SE_DRIVER_LIFETIME_VALUE        PSA_ATECC608A_LIFETIME
#endif



#endif// __PSA_DRIVER_SE_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
