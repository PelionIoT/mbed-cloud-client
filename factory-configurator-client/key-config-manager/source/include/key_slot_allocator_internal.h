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

#ifndef KEY_SLOT_ALLOCATOR_INTERNAL_H
#define KEY_SLOT_ALLOCATOR_INTERNAL_H

#include <inttypes.h>
#include "kcm_status.h"


/* Internal KSA APIs.
 * Those APIs are used internally by KSA module only.
 * Certificate Enrollment related tests use those APIs to simulate failing scenarios.
 */

 /** Retrieves ksa item id according to key name
 *
 * @key_name[IN] The name of the item
 * @key_name_size[IN] The size of the item name
 * @table_index[IN] The index of current ksa table
 * @ksa_id_type[IN] Type of ksa psa id
 * @psa_key_id[OUT] Value of ksa psa id
 *
 * @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
 */
kcm_status_e ksa_get_key_id(const uint8_t *item_name, size_t item_name_size, uint32_t table_index, ksa_id_type_e ksa_id_type, uint16_t *item_id);


/** Updates existing key's ksa id according to its type and value..
*
* @private_key_name[IN] The name of the private key
* @private_key_name_len[IN] The size of the private key name
* @key_id_type[IN] The type of the ksa id
* @id_value[IN] The value of the id to update.
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_update_key_id(const uint8_t *key_name, size_t key_name_size, ksa_id_type_e key_id_type, uint16_t id_value);

#endif //KEY_SLOT_ALLOCATOR_INTERNAL_H
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT


