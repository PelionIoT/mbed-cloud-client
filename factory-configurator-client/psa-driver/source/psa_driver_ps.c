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

#include "psa/protected_storage.h"
#include "kcm_defs.h"
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "psa_driver.h"


//next id to check if it is available to use
static uint16_t g_next_available_id = PSA_PS_MIN_ID_VALUE;  //next free id

/**
* Gets free PS id inside the defined range of KSA PS ids.
*
*    @param[in/out] ksa_id     Pointer to KSA PS id.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e psa_drv_ps_get_free_id(uint16_t* ksa_id_out)
{
    psa_status_t psa_status;
    struct psa_storage_info_t item_info;
    uint16_t id_index = PSA_INVALID_ID_NUMBER;
    uint16_t temp_id = PSA_INVALID_ID_NUMBER;
    bool is_free_id_found = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid ksa_id_out");

    /*Try to find a free id in the range of PSA_PS_MIN_ID_VALUE and PSA_PS_MAX_ID_VALUE
    The loop iterates from PSA_PS_MIN_ID_VALUE to PSA_PS_MAX_ID_VALUE. If  all PSA PS ID from this value and up to PSA_PS_MAX_ID_VALUE are occupied,
    the loop starts over from 0 up to original value of free_id. In this way the loop searches all psa id range to find an unoccupied id
    ------------------------------------------------------------------
    |                                |                               |
PSA_PS_MIN_ID_VALUE                free_id                  PSA_PS_MAX_ID_VALUE
                                     ================================>                 the first iteration search all ids from free_id to PSA_PS_MAX_ID_VALUE
    =================================>                                                 the second iteration search all ids from PSA_PS_MIN_ID_VALUE to free_id
    */
    for (id_index = g_next_available_id; id_index < (uint16_t)PSA_PS_MAX_ID_VALUE + g_next_available_id; id_index++) {

        temp_id = id_index;
        if (id_index >= (PSA_PS_MAX_ID_VALUE + 1)) {
            temp_id = (uint16_t)(PSA_PS_MIN_ID_VALUE + id_index) % (PSA_PS_MAX_ID_VALUE + 1);
        }

        if (temp_id != PSA_INVALID_ID_NUMBER) {
            psa_status = psa_ps_get_info((psa_storage_uid_t)temp_id, &item_info);
            if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
                is_free_id_found = true;
                break;
            }
        }
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_free_id_found == false), KCM_STATUS_OUT_OF_MEMORY, "Failed to find free PSA PS ID ");

    //Update out PSA id.
    *ksa_id_out = temp_id;

    //Update next id
    g_next_available_id = ++temp_id;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


static kcm_status_e create_psa_storage_flags(uint32_t extra_flags, psa_storage_create_flags_t* psa_storage_flags)
{

    //translate extra_flags to PSA flags
    if (extra_flags & PSA_PS_WRITE_ONCE_FLAG) {
        *psa_storage_flags |= PSA_STORAGE_FLAG_WRITE_ONCE;
    }

    if (!(extra_flags & PSA_PS_CONFIDENTIALITY_FLAG)) {
        *psa_storage_flags |= PSA_STORAGE_FLAG_NO_CONFIDENTIALITY;
    }
    if (!(extra_flags & PSA_PS_REPLAY_PROTECTION_FLAG)) {
        *psa_storage_flags |= PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION;
    }

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_ps_set(void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id)
{
    psa_status_t psa_status;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_storage_create_flags_t psa_create_flags = 0;
    struct psa_storage_info_t item_info;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //these bitmask is for unused bits in extra_flags.
    //only PSA_PS_WRITE_ONCE_FLAG, PSA_PS_CONFIDENTIALITY_FLAG and PSA_PS_REPLAY_PROTECTION_FLAG used  
    uint32_t psa_ps_flag_unused_bits_mask = (uint32_t)(~(PSA_PS_WRITE_ONCE_FLAG | PSA_PS_CONFIDENTIALITY_FLAG | PSA_PS_REPLAY_PROTECTION_FLAG));

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL) && (data_size > 0), KCM_STATUS_INVALID_PARAMETER, "invalid data length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((extra_flags & psa_ps_flag_unused_bits_mask) != 0, KCM_STATUS_INVALID_PARAMETER, "unused bits are set");

    kcm_status = psa_drv_ps_get_free_id(ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get free id");

    //check if the id already occupied
    psa_status = psa_ps_get_info(*ksa_id, &item_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(psa_status == PSA_SUCCESS, KCM_STATUS_FILE_EXIST, "Item already exists");

    kcm_status = create_psa_storage_flags(extra_flags, &psa_create_flags);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create PSA flags");

    psa_status = psa_ps_set((psa_storage_uid_t)*ksa_id, data_size, data, psa_create_flags);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return psa_drv_translate_to_kcm_error(psa_status);
}


kcm_status_e psa_drv_ps_get_data(const uint16_t ksa_id, void* data, size_t data_buffer_size, size_t* actual_data_size)
{
    psa_status_t psa_status;
    struct psa_storage_info_t item_info;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //TODO: remove once check for extra_flags is uncommented
    //PV_UNUSED_PARAM(extra_flags);

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_PS_MIN_RESERVED_VALUE) || (ksa_id > PSA_PS_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL) && (data_buffer_size > 0), KCM_STATUS_INVALID_PARAMETER, "invalid data length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((actual_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid data length");

    //check the size of data we need to read
    psa_status = psa_ps_get_info(ksa_id, &item_info);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF(psa_status == PSA_ERROR_DOES_NOT_EXIST, psa_drv_translate_to_kcm_error(psa_status), "Item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(psa_status != PSA_SUCCESS, psa_drv_translate_to_kcm_error(psa_status), "Failed to get data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(data_buffer_size < item_info.size, KCM_STATUS_INSUFFICIENT_BUFFER, "Insufficient buffer");

    //get the data
    psa_status = psa_ps_get((psa_storage_uid_t)ksa_id, 0, item_info.size, data, actual_data_size);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return psa_drv_translate_to_kcm_error(psa_status);
}



kcm_status_e psa_drv_ps_get_data_size(const uint16_t ksa_id, size_t* actual_data_size)
{
    psa_status_t psa_status;
    struct psa_storage_info_t item_info;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //TODO: remove once check for extra_flags is uncommented
    //PV_UNUSED_PARAM(extra_flags);

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_PS_MIN_RESERVED_VALUE) || (ksa_id > PSA_PS_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    //TODO: uncomment once test are fixed 
    //SA_PV_ERR_RECOVERABLE_RETURN_IF((extra_flags != 0), KCM_STATUS_INVALID_PARAMETER, "extra_flags are set");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((actual_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid data length");

    psa_status = psa_ps_get_info((psa_storage_uid_t)ksa_id, &item_info);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF(psa_status == PSA_ERROR_DOES_NOT_EXIST, psa_drv_translate_to_kcm_error(psa_status), "Item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(psa_status != PSA_SUCCESS, psa_drv_translate_to_kcm_error(psa_status), "Failed to get data size");

    *actual_data_size = item_info.size;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


kcm_status_e psa_drv_ps_remove(const uint16_t ksa_id)
{
    psa_status_t psa_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_PS_MIN_RESERVED_VALUE) || (ksa_id > PSA_PS_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);

    psa_status = psa_ps_remove((psa_storage_uid_t)ksa_id);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return psa_drv_translate_to_kcm_error(psa_status);
}

kcm_status_e psa_drv_ps_init_reserved_data(const uint16_t ksa_id, const void *data, size_t data_size)
{
    psa_status_t psa_status;
    struct psa_storage_info_t item_info;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_PS_MIN_RESERVED_VALUE) || (ksa_id > PSA_PS_MAX_RESERVED_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL) || (data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid data");

    //Get size of associated with current id
    psa_status = psa_ps_get_info((psa_storage_uid_t)ksa_id, &item_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_DOES_NOT_EXIST), psa_drv_translate_to_kcm_error(psa_status), "Failed to read reserved file");

    //If reserved file doesn't exists - create the new one with a reserved data
    if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
        //Save the file with next_available_crypto_id value
        psa_status = psa_ps_set((psa_storage_uid_t)ksa_id, data_size, data, PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to store reserved data file");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_ps_set_data_direct(const uint16_t ksa_id, const void *data, size_t data_size, uint32_t extra_flags)
{
    psa_status_t psa_status;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_storage_create_flags_t psa_create_flags = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_PS_MIN_RESERVED_VALUE) || (ksa_id > PSA_PS_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL) && (data_size > 0), KCM_STATUS_INVALID_PARAMETER, "Invalid data");

    kcm_status = create_psa_storage_flags(extra_flags, &psa_create_flags);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create PSA flags");

    //Set the file with a new data
    psa_status = psa_ps_set((psa_storage_uid_t)ksa_id, data_size, data, psa_create_flags);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to store the data");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
