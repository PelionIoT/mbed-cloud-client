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
// distributed under the License is distributed on an "AS IS" BASIS,get
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include <string.h>
#include "fcc_sotp.h"
#include "pv_error_handling.h"
#include "kcm_internal.h"

static bool get_sotp_type_size(sotp_type_e sotp_type, uint16_t *required_size_out)
{
    size_t required_size;

    switch (sotp_type) {
        case SOTP_TYPE_ROT:
            required_size = FCC_ROT_SIZE;
            break;
        case SOTP_TYPE_FACTORY_DONE:
            required_size = FCC_FACTORY_DISABLE_FLAG_SIZE;
            break;
        case SOTP_TYPE_RANDOM_SEED:
            required_size = FCC_ENTROPY_SIZE;
            break;
        case SOTP_TYPE_SAVED_TIME:
            required_size = sizeof(uint64_t);
            break;
        case SOTP_TYPE_TRUSTED_TIME_SRV_ID:
            required_size = FCC_CA_IDENTIFICATION_SIZE;
            break;
        default:
            SA_PV_LOG_ERR("Wrong sotp_type");
            return false;
    }

    // Success
    *required_size_out = (uint16_t)required_size;

    return true;
}

static fcc_status_e sotp_to_fcc_error_translation(sotp_result_e err)
{
    fcc_status_e fcc_result;
    switch(err)
    {
        case SOTP_SUCCESS:
            fcc_result = FCC_STATUS_SUCCESS;
            break;
        case SOTP_NOT_FOUND:
            fcc_result = FCC_STATUS_ITEM_NOT_EXIST;
            break;
        case SOTP_ALREADY_EXISTS:
            fcc_result = FCC_STATUS_INTERNAL_ITEM_ALREADY_EXIST;
            break;
        case SOTP_READ_ERROR:
        case SOTP_WRITE_ERROR:
        case SOTP_DATA_CORRUPT:
        case SOTP_BAD_VALUE:
        case SOTP_BUFF_TOO_SMALL:
        case SOTP_FLASH_AREA_TOO_SMALL:
        case SOTP_OS_ERROR:
        case SOTP_BUFF_NOT_ALIGNED:
        default:
            fcc_result = FCC_STATUS_STORE_ERROR;
            break;
    }
    return fcc_result;
}


fcc_status_e fcc_sotp_data_store(const uint8_t *data, size_t data_size, sotp_type_e sotp_type)
{
    bool success;
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[MAX_SOTP_BUFFER_SIZE / 8];
    uint16_t sotp_buffer_size = 0;

    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " sotp_type = %d", (uint32_t)data_size, (int)sotp_type);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid param data");

    success = get_sotp_type_size(sotp_type, &required_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_INVALID_PARAMETER, "Failed for get_sotp_type_size()");

    if (sotp_type != SOTP_TYPE_SAVED_TIME) {
        //Check if current type was already written to sotp by triyng to get the data
        sotp_result = sotp_get_item_size(sotp_type, &sotp_buffer_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result == SOTP_SUCCESS), FCC_STATUS_INTERNAL_ITEM_ALREADY_EXIST, "The item was already written to sotp");
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size != required_size), FCC_STATUS_INVALID_PARAMETER, "Wrong buf_size provided. Must be size of exactly %" PRIu32 " bytes", (uint32_t)required_size);

    // Write buf to SOTP. Cast is OK since size must be divisible by 8
    
    /*
    * Copy from data (uint8_t*) to aligned_8_bytes_buffer (uint64_t*) to make sure that data is 8 byte aligned.
    * Since sotp_set() gets a pointer to int64_t, if it is not aligned, and we just cast it to uint8_t*,
    * ARMCC functions like memcpy will assume 8 byte alignment resulting in possible access of unallocated memory. 
    */
    memcpy(aligned_8_bytes_buffer, data, data_size);

    sotp_result = sotp_set(sotp_type, (uint16_t)(data_size), (const uint32_t*)aligned_8_bytes_buffer);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS) , sotp_to_fcc_error_translation(sotp_result), "SOTP set failed");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return FCC_STATUS_SUCCESS;
}


fcc_status_e fcc_sotp_data_retrieve(uint8_t *data_out, size_t data_size_max, size_t *data_actual_size_out, sotp_type_e sotp_type)
{
    bool success;
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[MAX_SOTP_BUFFER_SIZE / 8] = {0};
    uint16_t actual_data_size = 0;

    SA_PV_LOG_INFO_FUNC_ENTER("data_out = %" PRIu32 " sotp_type = %d", (uint32_t)data_size_max, (int)sotp_type);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_out == NULL), FCC_STATUS_INVALID_PARAMETER, "invalid param data_out");

    success = get_sotp_type_size(sotp_type, &required_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_INVALID_PARAMETER, "Failed for get_sotp_type_size()");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size_max < required_size), FCC_STATUS_ERROR, "Wrong buf_size provided. Must be size of exactly %" PRIu32 " bytes", (uint32_t)required_size);

    // Retrieve buf from SOTP. Cast is OK since size must be multiple of 8
    sotp_result = sotp_get(sotp_type, (uint16_t)data_size_max, (uint32_t*)aligned_8_bytes_buffer, &actual_data_size);
    if (sotp_result == SOTP_NOT_FOUND) { //To prevent error log for positive flows
        return sotp_to_fcc_error_translation(sotp_result);
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS), sotp_to_fcc_error_translation(sotp_result), "SOTP_Get failed");

    // Copy from aligned buffer to callers uint8_t* buffer
    memcpy(data_out, aligned_8_bytes_buffer, actual_data_size);

    *data_actual_size_out = (size_t)(actual_data_size);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return FCC_STATUS_SUCCESS;
}

