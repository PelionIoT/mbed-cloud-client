/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
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

#ifndef NM_KVSTORE_HELPER_H_
#define NM_KVSTORE_HELPER_H_

/* Max value of KV_KEY_LENGTH */
#define KV_KEY_LENGTH 32

extern char kv_key_ws[KV_KEY_LENGTH];
extern char kv_key_br[KV_KEY_LENGTH];
extern char kv_key_tm[KV_KEY_LENGTH];

nm_status_t get_lenght_from_KVstore(char *key, size_t *len);
nm_status_t get_data_from_kvstore(char *key, uint8_t *value, size_t len);
nm_status_t set_data_to_kvstore(char *key, void *value, int len);

#endif /* NM_KVSTORE_HELPER_H_ */
