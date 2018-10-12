// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#include "FirmwareUpdateResource_stub.h"

#include "arm_uc_common.h"
#include "mbed-client/source/include/m2mcallbackstorage.h"
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
#include "mbed-client/m2mexecuteparams.h"
#endif
#include "mbed-client/m2mbase.h"
#include "source/update_client_hub_state_machine.h"
#include "source/update_client_hub_error_handler.h"
#include "test_datas.h"

//#include "mbed-trace/mbed_trace.h"
#include <stdio.h>

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

namespace FirmwareUpdateResource {

void packageCallback(void *, void *);
void packageCallbackUninitialized(void *, void *);
static void updateCallback(void *, void *);

static void (*externalUpdateCallback)(void) = NULL;
void (*externalPackageCallback)(const uint8_t *buffer, uint16_t length) = NULL;
bool initialized = false;
}

/**
 * @brief Initialize LWM2M Firmware Update ObjectW
 * @details Sets up LWM2M object with accompanying resources.
 */
void FirmwareUpdateResource::Initialize(void)
{
    printf("STUBBED FirmwareUpdateResource::Initialize()\n");
    initialized = true;
    _m2m_interface = NULL;
}

M2MObject *FirmwareUpdateResource::getObject()
{
    Initialize();

}


/*****************************************************************************/
/* Update Client Source                                                      */
/*****************************************************************************/

/* Add callback for resource /10252/0/1, Package */
int32_t FirmwareUpdateResource::addPackageCallback(void (*cb)(const uint8_t *buffer, uint16_t length))
{
    printf("STUBBED FirmwareUpdateResource::addPackageCallback: %p\n", cb);

    //mock().actualCall("addPackageCallBack");
    externalPackageCallback = cb;
    //packageCallbackSet = true;

}

void FirmwareUpdateResource::updateCallback(void *_parameters, void *_params)
{
    printf("STUBBED FirmwareUpdateResource::updateCallback \n");

    (void) _parameters;
    (void) _params;

    if (externalUpdateCallback) {
        /* invoke external callback function */
        externalUpdateCallback();

    }
}

void FirmwareUpdateResource::packageCallback(void *_parameters, void *_params)
{
    printf("STUBBED FirmwareUpdateResource::packageCallback\n");

    if (externalPackageCallback) {

        /* invoke external callback function */
        externalPackageCallback((const uint8_t *)manifest_test_case_data, sizeof(manifest_test_case_data));
    }
}


/*****************************************************************************/
/* Update Client Status                                                      */
/*****************************************************************************/

int32_t FirmwareUpdateResource::setM2MInterface(M2MInterface *interface)
{
    printf("STUBBED FirmwareUpdateResource::setM2MInterface\n");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (interface) {
        _m2m_interface = interface;
        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }
    return result;
}

M2MInterface *FirmwareUpdateResource::getM2MInterface(void)
{
    printf("STUBBED FirmwareUpdateResource::getM2MInterface\n");
    return _m2m_interface;
}

void FirmwareUpdateResource::Uninitialize(void)
{
    printf("STUBBED FirmwareUpdateResource::Uninitialize\n");
    initialized = false;
    _m2m_interface = NULL;
}

