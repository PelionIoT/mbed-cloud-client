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
#include "cn-cbor.h"
#include "pv_error_handling.h"
#include "fcc_bundle_utils.h"
#include "fcc_malloc.h"
#include "general_utils.h"
#include "fcc_utils.h"
#include "factory_configurator_client.h"
#include "storage_items.h"

#define  FCC_MAX_SIZE_OF_STRING 512

/** Gets name from cbor struct.
*
* @param text_cb[in]          The cbor text structure
* @param name_out[out]        The out buffer for string data
* @param name_len_out[out]    The actual size of output buffer
*
* @return
*     true for success, false otherwise.
*/
static bool get_data_name(const cn_cbor *text_cb, uint8_t **name_out, size_t *name_len_out)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((text_cb == NULL), false, "Cbor pointer is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((name_out == NULL), false, "Invalid pointer for name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((name_len_out == NULL), false, "Invalid pointer for name_len");

    *name_out = (uint8_t*)fcc_malloc((size_t)(text_cb->length));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*name_out == NULL), false, "Failed to allocate buffer for name");

    memcpy(*name_out, text_cb->v.bytes, (size_t)text_cb->length);
    *name_len_out = (size_t)text_cb->length;
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return true;
}

/** Gets data format from cbor struct
*
* The function goes over all formats and compares it with format from cbor structure.
*
* @param data_cb[in]         The cbor text structure
* @param data_format[out]    The format of data
*
* @return
*     true for success, false otherwise.
*/
static bool get_data_format(const cn_cbor *data_cb, fcc_bundle_data_format_e *data_format)
{

    int data_format_index;
    bool res;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_cb == NULL), false, "data_cb is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_format == NULL), false, "data_format is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*data_format != FCC_INVALID_DATA_FORMAT), false, "wrong data format value");

    for (data_format_index = 0; data_format_index < FCC_MAX_DATA_FORMAT - 1; data_format_index++) {
        res = is_memory_equal(fcc_bundle_data_format_lookup_table[data_format_index].data_format_name,
                              strlen(fcc_bundle_data_format_lookup_table[data_format_index].data_format_name),
                              data_cb->v.bytes,
                              (size_t)(data_cb->length));
        if (res) {
            *data_format = fcc_bundle_data_format_lookup_table[data_format_index].data_format_type;
            return true;
        }
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return false;
}

bool get_data_buffer_from_cbor(const cn_cbor *data_cb, uint8_t **out_data_buffer, size_t *out_size)
{

    cn_cbor_type cb_type;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_cb == NULL), false, "key_data_cb is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((out_size == NULL), false, "Size buffer is null ");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((out_data_buffer == NULL), false, "Data buffer is null");
    cb_type = data_cb->type;

    switch (cb_type) {
        case CN_CBOR_TAG:
            *out_data_buffer = (uint8_t*)data_cb->first_child->v.bytes;
            *out_size = (size_t)data_cb->first_child->length;
            break;
        case CN_CBOR_TEXT:
        case CN_CBOR_BYTES:
            *out_data_buffer = (uint8_t*)data_cb->v.bytes;
            *out_size = (size_t)(data_cb->length);
            break;
        case CN_CBOR_UINT:
            *out_data_buffer = (uint8_t*)(&(data_cb->v.uint));
            *out_size = (size_t)(data_cb->length);
            break;
        case CN_CBOR_INT:
            *out_data_buffer = (uint8_t*)(&(data_cb->v.sint));
            *out_size = (size_t)(data_cb->length);
            break;
        default:
            SA_PV_LOG_ERR("Invalid cbor data type (%u)!", data_cb->type);
            return false;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT("out_size=%" PRIu32 "", (uint32_t)*out_size);
    return true;
}
/** Frees all allocated memory of data parameter struct and sets initial values.
*
* @param data_param[in/out]    The data parameter structure
*/
void fcc_bundle_clean_and_free_data_param(fcc_bundle_data_param_s *data_param)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (data_param->name != NULL) {
        fcc_free(data_param->name);
        data_param->name = NULL;
    }

    if (data_param->private_key_name != NULL) {
        fcc_free(data_param->private_key_name);
        data_param->private_key_name = NULL;
    }

    data_param->array_cn = NULL;

    //FIXME - in case we will support pem, add additional pointer data_der, that will point to allocated
    // memory and will always released in case not NULL nad data pointer will relate to user buffer allways.
    /*if (data_param->data_der != NULL) {
    fcc_stats_free(data_param->data_der);
    data_param->data_der = NULL;
    }*/

    memset(data_param, 0, sizeof(fcc_bundle_data_param_s));
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

}
bool fcc_bundle_get_data_param(const cn_cbor *data_param_cb, fcc_bundle_data_param_s *data_param)
{
    bool status = false;
    int data_param_index = 0;
    cn_cbor *data_param_value_cb;
    fcc_bundle_data_param_type_e data_param_type;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Prepare key struct
    fcc_bundle_clean_and_free_data_param(data_param);

    //Go over all key's parameters and extract it to appropriate key struct member
    for (data_param_index = FCC_BUNDLE_DATA_PARAM_NAME_TYPE; data_param_index < FCC_BUNDLE_DATA_PARAM_MAX_TYPE; data_param_index++) {

        //Get value of parameter
        data_param_value_cb = cn_cbor_mapget_string(data_param_cb, fcc_bundle_data_param_lookup_table[data_param_index].data_param_name);

        if (data_param_value_cb != NULL) {
            //Get type of parameter
            data_param_type = fcc_bundle_data_param_lookup_table[data_param_index].data_param_type;

            switch (data_param_type) {
                case FCC_BUNDLE_DATA_PARAMETER_PRIVATE_KEY_NAME_TYPE:
                    status = get_data_name(data_param_value_cb, &(data_param->private_key_name), &(data_param->private_key_name_len));
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get private key  name");
                    break;

                case FCC_BUNDLE_DATA_PARAM_NAME_TYPE:
                    status = get_data_name(data_param_value_cb, &(data_param->name), &(data_param->name_len));
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get data parameter name");
                    break;

                case FCC_BUNDLE_DATA_PARAM_SCHEME_TYPE:
                    status = fcc_bundle_get_key_type(data_param_value_cb, (fcc_bundle_key_type_e*)&(data_param->type));
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get parameter type");
                    break;

                case FCC_BUNDLE_DATA_PARAM_FORMAT_TYPE:
                    status = get_data_format(data_param_value_cb, (fcc_bundle_data_format_e*)&(data_param->format));
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get key format");
                    break;

                case FCC_BUNDLE_DATA_PARAM_DATA_TYPE:
                    status = get_data_buffer_from_cbor(data_param_value_cb, &(data_param->data), &(data_param->data_size));
                    data_param->data_type = FCC_EXTERNAL_BUFFER_TYPE;
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get parameter data");
                    break;
                case FCC_BUNDLE_DATA_PARAM_ARRAY_TYPE:
                    data_param->array_cn = data_param_value_cb;
                    break;
                case FCC_BUNDLE_DATA_PARAM_ACL_TYPE:
                    status = get_data_buffer_from_cbor(data_param_value_cb, &(data_param->acl), &data_param->acl_size);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to get acl data");
                    break;
                default:
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((true), status = false, error_exit, "Parameter's field name is illegal");
            }//switch
        }//if
    }//for

    //FIXME: should be uncommented if PEM format is supported.
    /*
      if (data_param->format == FCC_PEM_DATA_FORMAT) {
          //status = convert_certificate_from_pem_to_der((uint8_t**)&(data_param->data), &(data_param->data_size));
          SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, error_exit, "Failed to convert the key from pem to der");
          //key->data_type = FCC_INTERNAL_BUFFER_TYPE;
      }
    */

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return status;

error_exit:
    fcc_bundle_clean_and_free_data_param(data_param);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return false;
}

fcc_status_e fcc_bundle_process_buffer(cn_cbor *cbor_bytes,const char *rbp_item_name, fcc_bundle_data_buffer_type_e buffer_type)
{
    uint8_t *buf;
    size_t buf_size;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    bool status;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    status = get_data_buffer_from_cbor(cbor_bytes, &buf, &buf_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status == false), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Unable to retrieve data from cn_cbor");
    
    
    switch (buffer_type) {
        case(FCC_BUNDLE_BUFFER_TYPE_ROT):
            fcc_status = fcc_rot_set(buf, buf_size);
            break;
        case(FCC_BUNDLE_BUFFER_TYPE_ENTROPY):
            fcc_status = fcc_entropy_set(buf, buf_size);
            break;
        default:
            fcc_status = FCC_STATUS_ERROR; // Internal error should not happens. If it does, there is a bug in the code
            break;
    }

    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit, "Unable to store data");

exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)rbp_item_name, strlen(rbp_item_name), fcc_status);
    }
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

fcc_status_e bundle_process_status_field(const cn_cbor *cbor_blob, char *cbor_group_name, size_t cbor_group_name_size, bool *fcc_field_status)
{
    uint8_t *buff = NULL;
    size_t buff_size;
    uint32_t fcc_field_value;
    bool status;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_blob == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Invalid param cbor_blob");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_blob->type != CN_CBOR_UINT), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Unexpected CBOR type");

    status = get_data_buffer_from_cbor(cbor_blob, &buff, &buff_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Unable to retrieve data from cn_cbor");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((buff_size != sizeof(fcc_field_value)), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Incorrect buffer size for field value");

    memcpy(&fcc_field_value, buff, buff_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((fcc_field_value != 0) && (fcc_field_value != 1)), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit,"Unexpected value, should be either 0 or 1");

    if (fcc_field_value == 1) {
        *fcc_field_status = true;
    }
    else {
        *fcc_field_status = false;
    }

exit:
    if (fcc_status != FCC_STATUS_SUCCESS)
    {
        // In case of fcc_store_error_info failure we would still rather return the previous caught error.
        (void)fcc_store_error_info((const uint8_t*)cbor_group_name, cbor_group_name_size, fcc_status);
    }
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
