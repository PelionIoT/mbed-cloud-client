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

#include "psa_driver.h"
#include "pv_log.h"

kcm_status_e psa_drv_translate_to_kcm_error(psa_status_t psa_status)
{
    kcm_status_e kcm_status;

    switch (psa_status) {
        case PSA_SUCCESS:
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        case PSA_ERROR_ALREADY_EXISTS:
            kcm_status = KCM_STATUS_FILE_EXIST;
            break;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            kcm_status = KCM_STATUS_INSUFFICIENT_BUFFER;
            break;
        case PSA_ERROR_DOES_NOT_EXIST:
            kcm_status = KCM_STATUS_ITEM_NOT_FOUND;
            break;
        case PSA_ERROR_NOT_PERMITTED:
            kcm_status = KCM_STATUS_NOT_PERMITTED;
            break;
        default:
            kcm_status = KCM_STATUS_ERROR;
            break;
    }

    if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
        SA_PV_LOG_TRACE("psa_status: %" PRId32", kcm_status: 0x%" PRIu32 "", (int32_t)psa_status, (uint32_t)kcm_status);
    } else if (psa_status != PSA_SUCCESS) {
        SA_PV_LOG_ERR("psa_status: %" PRId32", kcm_status: 0x%" PRIu32 "", (int32_t)psa_status, (uint32_t)kcm_status);
    }
    return kcm_status;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT


