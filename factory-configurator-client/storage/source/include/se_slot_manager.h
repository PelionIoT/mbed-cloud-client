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
#ifndef __SE_SLOT_MANAGER_H__
#define __SE_SLOT_MANAGER_H__


#include "kcm_defs.h"
#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "psa_driver.h"
#include "se_slot_manager_defs.h"

#ifdef __cplusplus
extern "C" {
#endif



    /** Populates SE slot tables.The tables correlate user defined SE slot with a specific psa ids.
    *
    */
    void sem_init(void);

    /** Finalizes resources of SEM module
    *
    */
    void sem_finalize(void);


    /** The function retrives a pointer to pre proviosioned table.
    *
    * @returns ::storage_se_preprovisioned_item_data_s pointer.
    */
    sem_preprovisioned_item_data_s* sem_get_preprovisioned_data(void);


    /** The function retrieves a number of preprovisioned items of SE.
    *
    * @returns ::uint16_t number of preprovisioned items.
    */
    size_t sem_get_num_of_preprovisioned_items(void);


    /** The function retrieves a number of non-locked SE slots according to type.
    *
    * @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise..
    */
    kcm_status_e sem_get_num_of_slots(uint32_t item_type_flag, uint16_t *num_of_slots);


    /** The function retrieves a slot number and psa id from the correlation table of the current type.
    *
    * @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise..
    */
    kcm_status_e sem_get_next_slot_and_psa_id(uint32_t item_type_flag, uint64_t *slot, uint16_t *psa_id);


    /** The function retrieves a specific psa id for current slot.
    *
    * @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise..
    */
    kcm_status_e sem_get_preprovisioned_psa_id(uint64_t slot, uint16_t *psa_id);


    /** The function retrieves a total number of SE slot in use.
    *
    */
    uint16_t sem_get_total_num_of_se_slots(void);

#ifdef __cplusplus
}
#endif

#endif //__SE_SLOT_MANAGER_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
