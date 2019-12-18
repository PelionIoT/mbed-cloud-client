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

#include <stdbool.h>
#include <inttypes.h>
#include "kcm_defs.h"
#include "pv_error_handling.h"
#include "storage_internal.h"
#include "storage_se_atmel.h"
#include "kcm_defs.h"
#include "key_slot_allocator.h"
#include "pv_macros.h"
#include "psa_driver_se_atmel.h"
#include "fcc_defs.h"
#include "storage_kcm.h"
#include "fcc_malloc.h"
#include "se_slot_manager.h"
#include "storage_se_atmel.h"
#include "se_data_user_config.h"
#include "psa_driver.h"

typedef struct sem_psa_correlation {
    uint64_t slot_num;
    uint16_t psa_id;
} sem_psa_correlation_s;

/*Total number of SE slot in usage*/
#define SEM_SLOTS_TOTAL_NUMBER                    SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS + SE_DATA_PRIV_KEY_SLOTS_NUMBER + SE_DATA_PUB_KEY_SLOTS_NUMBER
/*Total number of SE slots for keys in usage*/
#define SEM_KEYS_SLOTS_TOTAL_NUMBER               SE_DATA_PRIV_KEY_SLOTS_NUMBER + SE_DATA_PUB_KEY_SLOTS_NUMBER
/*Min value of psa id used by SE slots , the range is taken from crypto driver range */
#define SEM_PSA_IDS_MIN_VALUE                     PSA_CRYPTO_SE_IDS_MIN_VALUE
/*Max value of psa id used by SE slots , the range is taken from crypto driver range */
#define SEM_PSA_IDS_MAX_VALUE                     SEM_PSA_IDS_MIN_VALUE + SEM_SLOTS_TOTAL_NUMBER
/*Min value of psa ids for preprovisioned items*/
#define SEM_PREPROVISIONED_IDS_MIN_VALUE          SEM_PSA_IDS_MIN_VALUE
/*Min value of psa ids for private key items*/
#define SEM_PRIV_KEY_IDS_MIN_VALUE                SEM_PREPROVISIONED_IDS_MIN_VALUE + SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS
/*Min value of psa ids for public key items*/
#define SEM_PUB_KEY_IDS_MIN_VALUE                SEM_PRIV_KEY_IDS_MIN_VALUE + SE_DATA_PUB_KEY_SLOTS_NUMBER


uint16_t g_ssm_current_priv_key_index = 0;
uint16_t g_ssm_current_pub_key_index = 0;
uint16_t g_ssm_current_preprovisioned_index = 0;
bool g_sem_initialized = false;

uint64_t g_preprovisioned_slots[SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS] = { 0 };
sem_psa_correlation_s g_sem_priv_slot_psa_correlation_table[SE_DATA_PRIV_KEY_SLOTS_NUMBER];
sem_psa_correlation_s g_sem_pub_slot_psa_correlation_table[SE_DATA_PUB_KEY_SLOTS_NUMBER];
sem_psa_correlation_s g_sem_preprovisioned_slot_psa_correlation_table[SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS];


/*The function populates correlation table of current type slot array according to the passed parameters*/
static void populate_correlation_table(sem_psa_correlation_s *table, int max_index, uint64_t *slots_array, uint16_t psa_start_value)
{
    int index = 0;

    for (index = 0; index < max_index; index++) {
        (table + index)->slot_num = (uint64_t)*(slots_array + index);
        (table + index)->psa_id = (uint16_t)psa_start_value + index;
    }
}
/*The gets slot and psa id of lat index and incremnets the last index.*/
static void get_slot_and_id(sem_psa_correlation_s *table, uint64_t *slot, uint16_t *psa_id, uint16_t *g_last_index, int max_index_value)
{
    *slot = (table + *g_last_index)->slot_num;//    g_private_key_slots[g_ssm_current_priv_key_index].slot_num;
    *psa_id = (table + *g_last_index)->psa_id;//   g_private_key_slots[g_ssm_current_priv_key_index].psa_id;
    (*g_last_index)++; //Increase the counter of current type
    if (*g_last_index > max_index_value) { //If the value reached the max value, restart from 0
        *g_last_index = 0;
    }
}
static void populate_preproviosioned_slot_array()
{
    for (size_t index = 0; index < SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS; index++) {
        g_preprovisioned_slots[index] = g_sem_preprovisioned_data[index].se_slot_num;
    }
}

void sem_init(void)
{

    /* Populate correlation table of pre provsioned items */
    populate_preproviosioned_slot_array( );
   /* Populate correlation table of pre provsioned items */
    populate_correlation_table(g_sem_preprovisioned_slot_psa_correlation_table, SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS, g_preprovisioned_slots, (uint16_t)(SEM_PSA_IDS_MIN_VALUE));
    /* Populate correlation table of private keys */
    populate_correlation_table(g_sem_priv_slot_psa_correlation_table, SE_DATA_PRIV_KEY_SLOTS_NUMBER, g_private_key_slots, (uint16_t)(SEM_PRIV_KEY_IDS_MIN_VALUE));
    /* Populate correlation table of public keys */
    populate_correlation_table(g_sem_pub_slot_psa_correlation_table, SE_DATA_PUB_KEY_SLOTS_NUMBER, g_public_key_slots, (uint16_t)(SEM_PUB_KEY_IDS_MIN_VALUE));

    g_ssm_current_priv_key_index = 0;
    g_ssm_current_pub_key_index = 0;
    g_ssm_current_preprovisioned_index = 0;

    g_sem_initialized = true;
}
void sem_finalize(void)
{
    memset(g_sem_preprovisioned_slot_psa_correlation_table, 0, sizeof(g_sem_preprovisioned_slot_psa_correlation_table));
    memset(g_sem_priv_slot_psa_correlation_table, 0, sizeof(g_sem_priv_slot_psa_correlation_table));
    memset(g_sem_pub_slot_psa_correlation_table, 0, sizeof(g_sem_pub_slot_psa_correlation_table));

    g_ssm_current_priv_key_index = 0;
    g_ssm_current_pub_key_index = 0;
    g_ssm_current_preprovisioned_index = 0;

    g_sem_initialized = false;
}

sem_preprovisioned_item_data_s* sem_get_preprovisioned_data(void)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    return (sem_preprovisioned_item_data_s*)g_sem_preprovisioned_data;
}

uint16_t sem_get_total_num_of_se_slots(void)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    return (uint16_t)(SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS + SE_DATA_PRIV_KEY_SLOTS_NUMBER + SE_DATA_PUB_KEY_SLOTS_NUMBER);
}

size_t sem_get_num_of_preprovisioned_items(void)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    return (uint16_t)SE_DATA_NUMBER_OF_PREPROVISIONED_ITEMS;
}

kcm_status_e sem_get_num_of_slots(uint32_t item_type_flag, uint16_t *num_of_slots)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    switch (item_type_flag) {
        case PSA_CRYPTO_PRIVATE_KEY_FLAG:
            *num_of_slots = (uint16_t)SE_DATA_PRIV_KEY_SLOTS_NUMBER;
            break;
        case PSA_CRYPTO_PUBLIC_KEY_FLAG:
            *num_of_slots = (uint16_t)SE_DATA_PUB_KEY_SLOTS_NUMBER;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");
    }
    return KCM_STATUS_SUCCESS;
}


kcm_status_e sem_get_next_slot_and_psa_id(uint32_t item_type_flag, uint64_t *slot, uint16_t *psa_id)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    switch (item_type_flag) {
        case PSA_CRYPTO_PRIVATE_KEY_FLAG:
            get_slot_and_id(g_sem_priv_slot_psa_correlation_table, slot, psa_id, &g_ssm_current_priv_key_index, SE_DATA_PRIV_KEY_SLOTS_NUMBER);
            break;
        case PSA_CRYPTO_PUBLIC_KEY_FLAG:
            get_slot_and_id(g_sem_pub_slot_psa_correlation_table, slot, psa_id, &g_ssm_current_pub_key_index, SE_DATA_PUB_KEY_SLOTS_NUMBER);
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");
    }
    return KCM_STATUS_SUCCESS;

}

kcm_status_e sem_get_preprovisioned_psa_id(uint64_t slot, uint16_t *psa_id)
{
    if (!g_sem_initialized) {
        sem_init();
    }

    for (size_t index = 0; index < sizeof(g_sem_preprovisioned_slot_psa_correlation_table); index++) {
        if (slot == g_sem_preprovisioned_slot_psa_correlation_table[index].slot_num) {
            *psa_id = g_sem_preprovisioned_slot_psa_correlation_table[index].psa_id;
            return KCM_STATUS_SUCCESS;
        }
    }
    return KCM_STATUS_ITEM_NOT_FOUND;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
