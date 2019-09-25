/*
 * Copyright (c) 2019 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed-client/m2mdevice_handlers.h"
#include "mbed-client/mbed_client_weak.h"
#include "CloudClientDefaultResourceHandlers.h"
#include "key_config_manager.h"
#include "pal.h"


void m2mdevice_reboot_execute() {

    cloud_client_reboot();
}

void m2mdevice_factory_reset_execute() {

    cloud_client_factory_reset();
}

MBED_CLIENT_WEAK_FUNCTION void cloud_client_reboot() {

    pal_osReboot();
}

MBED_CLIENT_WEAK_FUNCTION void cloud_client_factory_reset() {

    kcm_factory_reset();
}
