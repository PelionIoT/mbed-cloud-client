// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#ifndef __SE_SLOT_MANAGER_DEFS_H__
#define __SE_SLOT_MANAGER_DEFS_H__

#include "kcm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* Structure that represents SE pre provisioned data*/
    typedef struct sem_preprovisioned_item_data_ {
        kcm_item_type_e  kcm_item_type;
        const char *kcm_item_name;
        uint16_t se_slot_num;
    } sem_preprovisioned_item_data_s;


#ifdef __cplusplus
}
#endif

#endif //__SE_SLOT_MANAGER_DEFS_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
