// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_NVM_INT_H_
#define __FOTA_NVM_INT_H_

#include "fota/fota_base.h"

#if MBED_CLOUD_CLIENT_FOTA_ENABLE

#ifdef __cplusplus
extern "C" {
#endif

#include "CloudClientStorage.h"

#if (MBED_CLOUD_CLIENT_PROFILE == MBED_CLOUD_CLIENT_PROFILE_LITE)

typedef uint8_t ccs_item_type_e;

#define CCS_PRIVATE_KEY_ITEM   0x1
#define CCS_PUBLIC_KEY_ITEM    0x2
#define CCS_SYMMETRIC_KEY_ITEM 0x4
#define CCS_CERTIFICATE_ITEM   0x8
#define CCS_CONFIG_ITEM        0x10

#else  // (MBED_CLOUD_CLIENT_PROFILE == MBED_CLOUD_CLIENT_PROFILE_FULL)

typedef const char * cloud_client_param;

#define UPDATE_VENDOR_ID                        "pelion_wCfgParam_mbed.VendorId" // "FWVendorId"
#define UPDATE_CLASS_ID                         "pelion_wCfgParam_mbed.ClassId" // "FWClassId"
#define UPDATE_CERTIFICATE                      "pelion_wCrtae_mbed.UpdateAuthCert" // "FWUpdateCert"
#define UPDATE_PUBKEY                           "pelion_wCrtae_mbed.UpdatePubKey"
#define FOTA_ENCRYPT_KEY                        "FOTA_ENCRYPT_KEY" // "FTEncryptKey"
#define FOTA_SALT_KEY                           "FOTA_SALT_KEY" // ""FTSaltKey"
#define FOTA_MANIFEST_KEY                       "FOTA_MANIFEST_KEY" // ""FTManKey"
#define FOTA_COMP_VER_BASE                      "FTCmpV"

#endif  // (MBED_CLOUD_CLIENT_PROFILE == MBED_CLOUD_CLIENT_PROFILE_LITE)

int fota_nvm_get(cloud_client_param key, uint8_t *buffer, size_t buffer_size, size_t *bytes_read, ccs_item_type_e item_type);

int fota_nvm_set(cloud_client_param key, const uint8_t *buffer, size_t buffer_size, ccs_item_type_e item_type);

int fota_nvm_remove(cloud_client_param key, ccs_item_type_e item_type);

#ifdef __cplusplus
}
#endif
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
#endif //__FOTA_NVM_INT_H_
