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

#ifndef ARM_PAL_KV_H
#define ARM_PAL_KV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define ARM_PAL_KV_KEY_MAX_PATH 220

typedef struct arm_pal_key_value_api {
    uint32_t (*keySize)();
    void (*keyInit)(void *key);

    int32_t (*Close)(void *hkey);
    int32_t (*Create)(const char *key_name, size_t value_len, const void *kdesc, void *hkey);
    int32_t (*Delete)(void *hkey);
    int32_t (*Find)(const char *key_name_query, const void *previous, void *next);
    int32_t (*Flush)(void);
    int32_t (*GetKeyName)(void *hkey, char *key_name, uint8_t *key_len);
    int32_t (*GetValueLen)(void *hkey, size_t *value_len);
    int32_t (*Initialize)(
        void(*callback)(int32_t status, int32_t cmd_code, void *client_context, void *handle),
        void *client_context);
    int32_t (*PowerControl)(uint32_t state);
    int32_t (*Read)(void *hkey, void *data, size_t *len);
    int32_t (*Open)(const char *key_name, uint32_t flags, void *hkey);
    int32_t (*Rseek)(void *hkey, size_t offset);
    int32_t (*Uninitialize)(void);
    int32_t (*Write)(void *hkey, const char *data, size_t *len);
} arm_pal_key_value_api;


#define ARM_PAL_KV_OPENMODE_RD (1 << 3)

uint32_t ARM_PAL_KV_keySize(const arm_pal_key_value_api *api);
void ARM_PAL_KV_keyInit(const arm_pal_key_value_api *api, void *key);
int32_t ARM_PAL_KV_Close(const arm_pal_key_value_api *api, void *hkey);
int32_t ARM_PAL_KV_Create(const arm_pal_key_value_api *api, const char *key_name, size_t value_len, const void *kdesc,
                          void *hkey);
int32_t ARM_PAL_KV_Delete(const arm_pal_key_value_api *api, void *hkey);
int32_t ARM_PAL_KV_Find(const arm_pal_key_value_api *api, const char *key_name_query, const void *previous, void *next);
int32_t ARM_PAL_KV_Flush(const arm_pal_key_value_api *api);
int32_t ARM_PAL_KV_GetKeyName(const arm_pal_key_value_api *api, void *hkey, char *key_name, uint8_t *key_len);
int32_t ARM_PAL_KV_GetValueLen(const arm_pal_key_value_api *api, void *hkey, size_t *value_len);
int32_t ARM_PAL_KV_Initialize(const arm_pal_key_value_api *api, void(*callback)(int32_t status, int32_t cmd_code,
                                                                                void *client_context, void *handle), void *client_context);
int32_t ARM_PAL_KV_PowerControl(const arm_pal_key_value_api *api, uint32_t state);
int32_t ARM_PAL_KV_Read(const arm_pal_key_value_api *api, void *hkey, void *data, size_t *len);
int32_t ARM_PAL_KV_Open(const arm_pal_key_value_api *api, const char *key_name, uint32_t flags, void *hkey);
int32_t ARM_PAL_KV_Rseek(const arm_pal_key_value_api *api, void *hkey, size_t offset);
int32_t ARM_PAL_KV_Uninitialize(const arm_pal_key_value_api *api);
int32_t ARM_PAL_KV_Write(const arm_pal_key_value_api *api, void *hkey, const char *data, size_t *len);




#ifdef __cplusplus
}
#endif


#endif // ARM_PAL_KV_H
