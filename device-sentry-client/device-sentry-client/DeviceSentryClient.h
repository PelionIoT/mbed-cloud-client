// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef DEVICE_SENTRY_CLIENT_H
#define DEVICE_SENTRY_CLIENT_H

#include "mbed-client/m2minterface.h"
#include "ds_status.h"

/** Class used for tracking device metrics and platform health
 *
 * @note Synchronization level: Not protected against multithreading
 */
namespace DeviceSentryClient
{

/**
 *  @brief Initialize Mbed Cloud Client Device Sentry resources and infrastructure.
 *
 *  @param registration_list Mbed Cloud Client resource objects list
 *  @return DS_STATUS_SUCCESS on success, or some error if failed
 */
ds_status_e init(M2MBaseList& registration_list);

/**
 * @brief Finalizes Device Sentry resources.
 * 
 */
void finalize();

};

#endif // DEVICE_SENTRY_CLIENT_H
