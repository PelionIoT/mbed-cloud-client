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
#include "fcc_bundle_handler.h"
#include "pv_error_handling.h"
#include "fcc_bundle_utils.h"
#include "fcc_malloc.h"
#include "general_utils.h"
#include "fcc_utils.h"
#include "factory_configurator_client.h"
#include "storage_kcm.h"

fcc_status_e fcc_bundle_process_rbp_buffer(CborValue *tcbor_top_map, const char *map_key_name, const char *rbp_item_name)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    bool status;
    CborError tcbor_error = CborNoError;
    CborValue tcbor_val;
    const uint8_t *buf;
    size_t buf_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    tcbor_error = cbor_value_map_find_value(tcbor_top_map, map_key_name, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed to get %s",map_key_name);

    if (!cbor_value_is_valid(&tcbor_val)) {
        // map_key_name not found in map, skip processing
        return FCC_STATUS_SUCCESS;
    }

    status = fcc_bundle_get_byte_string(&tcbor_val, &buf, &buf_size, NULL, 0);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Failed to get rbp buffer");    

    if (strcmp(rbp_item_name, STORAGE_RBP_RANDOM_SEED_NAME) == 0) {
        fcc_status = fcc_entropy_set(buf, buf_size);
    } else if (strcmp(rbp_item_name, STORAGE_RBP_ROT_NAME) == 0) {
        fcc_status = fcc_rot_set(buf, buf_size);
    } else {
        return FCC_STATUS_ERROR; // Internal error should not happens. If it does, there is a bug in the code
    }

    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit, "Unable to store data");

exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)rbp_item_name, strlen(rbp_item_name), fcc_status);
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

fcc_status_e fcc_bundle_factory_disable( void )
{

    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    fcc_status = fcc_factory_disable();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit, "Failed to set factory disable flag");

exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)STORAGE_RBP_FACTORY_DONE_NAME, strlen(STORAGE_RBP_FACTORY_DONE_NAME), fcc_status);
    }
    return fcc_status;
}

bool fcc_bundle_get_text_string(const CborValue *tcbor_val, const char **str, size_t *str_len, const char *err_field_name, size_t err_field_name_len)
{
    bool status = true;
    CborError tcbor_error = CborNoError;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_text_string(tcbor_val)), status = false, exit, "Unexpected CBOR type");

    tcbor_error = cbor_value_get_text_string_chunk(tcbor_val, str, str_len, NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((str == NULL), status = false, exit,"Unexpected value");

exit:
    if (status == false && err_field_name != NULL)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)err_field_name, err_field_name_len, FCC_STATUS_BUNDLE_ERROR);
    }
    return status;
}

bool fcc_bundle_get_byte_string(const CborValue *tcbor_val, const uint8_t **bytes, size_t *bytes_len, const char *err_field_name, size_t err_field_name_len)
{
    bool status = true;
    CborError tcbor_error = CborNoError;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_byte_string(tcbor_val)), status = false, exit, "Unexpected CBOR type");

    tcbor_error = cbor_value_get_byte_string_chunk(tcbor_val, bytes, bytes_len, NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((bytes == NULL), status = false, exit,"Unexpected value");

exit:
    if (status == false && err_field_name != NULL)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)err_field_name, err_field_name_len, FCC_STATUS_BUNDLE_ERROR);
    }
    return status;
}

bool fcc_bundle_get_uint64(const CborValue *tcbor_val, uint64_t *value_out, const char *err_field_name, size_t err_field_name_len)
{
    bool status = true;
    CborError tcbor_error = CborNoError;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_unsigned_integer(tcbor_val)), status = false, exit, "Unexpected CBOR type");

    tcbor_error = cbor_value_get_uint64(tcbor_val, value_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");

exit:
    if (status == false && err_field_name != NULL)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)err_field_name, err_field_name_len, FCC_STATUS_BUNDLE_ERROR);
    }
    return status;
}

bool fcc_bundle_get_bool(const CborValue *tcbor_val, bool *value_out, const char *err_field_name, size_t err_field_name_len)
{
    bool status = true;
    int value = 0;
    CborError tcbor_error = CborNoError;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_integer(tcbor_val)), status = false, exit, "Unexpected CBOR type");

    tcbor_error = cbor_value_get_int(tcbor_val, &value);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((value != 0) && (value != 1)), status = false, exit,"Unexpected bool value, should be either 0 or 1");

    *value_out = (value == 1);

exit:
    if (status == false && err_field_name != NULL)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)err_field_name, err_field_name_len, FCC_STATUS_BUNDLE_ERROR);
    }
    return status;
}

/** Get pointer to the start of the data. 
 *  In case of fixed type, get the value to data64_val and set data_ptr to it's address.
 *  data64_val can be NULL if fixed types not expected. */
bool fcc_bundle_get_variant(CborValue *tcbor_val, const uint8_t **data_ptr, size_t *data_ptr_size, uint64_t *data64_val, const char *err_field_name, size_t err_field_name_len)
{
    bool status = true;
    CborError tcbor_error = CborNoError;
    CborType tcbor_type;
    CborTag tcbor_tag;

    *data_ptr = NULL;

    tcbor_type = cbor_value_get_type(tcbor_val);

    if (tcbor_type == CborTagType) {
        // Tags
        tcbor_error = cbor_value_get_tag(tcbor_val, &tcbor_tag);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");
        tcbor_error = cbor_value_skip_tag(tcbor_val);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");

        // check if known and supported tag
        switch (tcbor_tag)
        {
            case CborPositiveBignumTag:
                // do nothing, continue parsing
                break;         
            default:
                SA_PV_ERR_RECOVERABLE_GOTO_IF((true), status = false, exit, "Unexpected CBOR tag type");
        }
        // get type of tat's value
        tcbor_type = cbor_value_get_type(tcbor_val);
    }

    switch (tcbor_type)
    {
        case CborIntegerType:
            SA_PV_ERR_RECOVERABLE_GOTO_IF((data64_val == NULL), status = false, exit, "Unexpected CBOR type");

            if (cbor_value_is_unsigned_integer(tcbor_val)) {
                tcbor_error = cbor_value_get_uint64(tcbor_val, data64_val);
            } else {
                tcbor_error = cbor_value_get_int64(tcbor_val, (int64_t*)data64_val);
            }
            *data_ptr = (const uint8_t*)data64_val;
            *data_ptr_size = sizeof(uint64_t);
            break;
        case CborByteStringType:
            tcbor_error = cbor_value_get_byte_string_chunk(tcbor_val, (const uint8_t**)data_ptr, data_ptr_size, NULL);
            break;
        case CborTextStringType:
            tcbor_error = cbor_value_get_text_string_chunk(tcbor_val, (const char**)data_ptr, data_ptr_size, NULL);
            break;
        default:
            SA_PV_ERR_RECOVERABLE_GOTO_IF((true), status = false, exit, "Unexpected CBOR type");
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), status = false, exit, "Unexpected CBOR error");

exit:
    if (status == false && err_field_name != NULL)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)err_field_name, err_field_name_len, FCC_STATUS_BUNDLE_ERROR);
    }
    return status;
}

fcc_status_e fcc_bundle_process_maps_in_arr(const CborValue *tcbor_arr_val ,fcc_bundle_process_map_cb process_map_cb, void *extra_cb_info)
{
    CborError tcbor_error = CborNoError;
    CborValue tcbor_val;
    CborValue tcbor_map_val;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((!cbor_value_is_array(tcbor_arr_val)), FCC_STATUS_BUNDLE_ERROR, "Unexpected CBOR type");

    // Enter array container
    tcbor_error = cbor_value_enter_container(tcbor_arr_val, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed parsing array");

    // go over the array elements (maps) and call fcc_bundle_process_map for each map
    while (!cbor_value_at_end(&tcbor_val)) {

        SA_PV_ERR_RECOVERABLE_RETURN_IF((!cbor_value_is_map(&tcbor_val)), FCC_STATUS_BUNDLE_ERROR, "Unexpected CBOR type");

        // Enter map container
        tcbor_error = cbor_value_enter_container(&tcbor_val ,&tcbor_map_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed parsing map");

        // call process_map_cb callback
        fcc_status = process_map_cb(&tcbor_map_val, extra_cb_info);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Failed parsing map");
        
        // advance tcbor_val to next element in array
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed parsing array");

    } // end loop element

    return FCC_STATUS_SUCCESS;
}
