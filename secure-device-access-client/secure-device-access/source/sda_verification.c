// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#include "sda_error_handling.h"
#include "sda_malloc.h"
#include "sda_internal_defs.h"
#include "secure_device_access.h"
#include "string.h"
#include "sda_verification.h"
#include "sda_cose.h"
#include "sda_trust_anchor.h"
#include "sda_nonce_mgr.h"
#include "sda_data_token.h"
#include "sda_nonce_mgr.h"
#include "key_config_manager.h"
#include "fcc_defs.h"

#define SDA_GARCE_TIME_PERIOD 300 //cwt parameters - "nbf" and "exp" should be verified with a grace period of 5 minutes(to allow for small clock drift between device and AS)

const char g_device_id_parameter_name[] = "mbed.InternalEndpoint";

/* The function checks audience type and returns its data and type.
*  In case the function failed to detect audience type its return an error.
*/
static sda_status_internal_e sda_audience_data_get(const uint8_t *audience_instance, size_t audience_instance_size, sda_audience_data_s *audience_data)
{
    int res = 0;
    sda_audience_type_e sda_temp_audience_type;
    size_t size_of_audience_prefix = 0;

    SDA_LOG_TRACE_FUNC_ENTER("audience_instance_size=%" PRIu32, (uint32_t)audience_instance_size);

    for (sda_temp_audience_type = SDA_DEVICE_ID_AUDIENCE_TYPE; sda_temp_audience_type < SDA_MAX_AUDIENCE_TYPE; sda_temp_audience_type++) {
        switch (sda_temp_audience_type) {
            case SDA_DEVICE_ID_AUDIENCE_TYPE:
                //Try to find device id type string in the current audience instance
                res = memcmp(audience_instance, SDA_AUDIENCE_DEVICE_ID_TYPE_STRING, strlen(SDA_AUDIENCE_DEVICE_ID_TYPE_STRING));
                if (res == 0) {
                    size_of_audience_prefix = strlen(SDA_AUDIENCE_DEVICE_ID_TYPE_STRING);
                } else {
                    res = memcmp(audience_instance, SDA_AUDIENCE_DEVICE_ID_TYPE_STRING_OLD, strlen(SDA_AUDIENCE_DEVICE_ID_TYPE_STRING_OLD));
                    if (res == 0) {
                        size_of_audience_prefix = strlen(SDA_AUDIENCE_DEVICE_ID_TYPE_STRING_OLD);
                    } else {
                        break;
                    }
                }
                //Update out type and audience data with device id string
                audience_data->audience_data = (uint8_t *)audience_instance + size_of_audience_prefix;
                audience_data->audience_data_type = sda_temp_audience_type;
                audience_data->audience_data_size = audience_instance_size - size_of_audience_prefix;
                return SDA_STATUS_INTERNAL_SUCCESS;
            case SDA_ENDPONT_NAME_AUDIENCE_TYPE:
                //Try to find endpoint name type string in the current audience instance
                res = memcmp(audience_instance, SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING, strlen(SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING));
                if (res == 0) {
                    size_of_audience_prefix = strlen(SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING);
                } else {
                    res = memcmp(audience_instance, SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING_OLD, strlen(SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING_OLD));
                    if (res == 0) {
                        size_of_audience_prefix = strlen(SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING_OLD);
                    } else {
                        break;
                    }
                }
                //Update out type and audience data with endpoint name string
                audience_data->audience_data = (uint8_t *)audience_instance + size_of_audience_prefix;
                audience_data->audience_data_type = sda_temp_audience_type;
                audience_data->audience_data_size = audience_instance_size - size_of_audience_prefix;
                return SDA_STATUS_INTERNAL_SUCCESS;
            default:
                SDA_LOG_INFO("Wrong type og audience");
                return SDA_STATUS_INTERNAL_GENERAL_ERROR;
        }
    }

    SDA_LOG_TRACE_FUNC_EXIT("status=SDA_STATUS_INTERNAL_GENERAL_ERROR");

    return SDA_STATUS_INTERNAL_GENERAL_ERROR;
}


static sda_status_internal_e sda_device_audience_verify(sda_audience_data_s *cwt_audience_data, sda_device_audience_data_s *device_audience_data)
{
    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check format of audience data
    switch (cwt_audience_data->audience_data_type) {
        case SDA_DEVICE_ID_AUDIENCE_TYPE:
            //Check against  device id data
            if ((cwt_audience_data->audience_data_size != SDA_DEVICE_ID_STRING_SIZE_IN_BYTES) ||
                    (memcmp(device_audience_data->device_id, cwt_audience_data->audience_data, SDA_DEVICE_ID_STRING_SIZE_IN_BYTES) != 0)) {
                return SDA_STATUS_INTERNAL_AUDIENCE_ERROR;
            }
            break;
        case SDA_ENDPONT_NAME_AUDIENCE_TYPE:
            //Check audience data size
            if ((cwt_audience_data->audience_data_size != device_audience_data->device_endpoint_name_size) ||
                    (memcmp(device_audience_data->device_endpoint_name, cwt_audience_data->audience_data, cwt_audience_data->audience_data_size) != 0)) {
                return SDA_STATUS_INTERNAL_AUDIENCE_ERROR;
            }
            break;
        default:
            SDA_LOG_INFO("Wrong type og audience");
            return SDA_STATUS_INTERNAL_GENERAL_ERROR;
    }

    SDA_LOG_TRACE_FUNC_EXIT("status=SDA_STATUS_INTERNAL_SUCCESS");
    return SDA_STATUS_INTERNAL_SUCCESS;
}

static sda_status_internal_e sda_device_audience_data_get(sda_device_audience_data_s *device_audience_data)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t audience_data_size = 0;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // Get endpoint name from kcm
    kcm_status = kcm_item_get_data((uint8_t *)g_fcc_endpoint_parameter_name,
                                   strlen(g_fcc_endpoint_parameter_name),
                                   KCM_CONFIG_ITEM,
                                   device_audience_data->device_endpoint_name,
                                   sizeof(device_audience_data->device_endpoint_name),
                                   &audience_data_size);
    SDA_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), SDA_STATUS_INTERNAL_KCM_ERROR, "KCM get failed. KCM status %d", kcm_status);
    device_audience_data->device_endpoint_name_size = audience_data_size;


    // Get device id from kcm
    kcm_status = kcm_item_get_data((uint8_t *)g_device_id_parameter_name,
                                   strlen(g_device_id_parameter_name),
                                   KCM_CONFIG_ITEM,
                                   device_audience_data->device_id,
                                   sizeof(device_audience_data->device_id),
                                   &audience_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return SDA_STATUS_INTERNAL_SUCCESS; // it's an optional parameter
    }

    SDA_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), SDA_STATUS_INTERNAL_KCM_ERROR, "Failed to get a valid device ID");
    SDA_ERR_RECOVERABLE_RETURN_IF((audience_data_size != SDA_DEVICE_ID_STRING_SIZE_IN_BYTES), SDA_STATUS_INTERNAL_KCM_ERROR, "Invalid device ID size (%u)", (unsigned int)audience_data_size);

    SDA_LOG_TRACE_FUNC_EXIT("status=SDA_STATUS_INTERNAL_SUCCESS");
    return SDA_STATUS_INTERNAL_SUCCESS;
}

sda_status_internal_e sda_audience_verify_tiny(const uint8_t *audience_array_ptr, size_t audience_array_size)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    size_t audience_array_length = 0;
    CborValue current_audience_data;
    CborValue audience_array;
    uint8_t *current_audience_buffer = NULL;
    size_t current_audience_buffer_size = 0;
    sda_audience_data_s audience_data = { 0 };
    bool status = false;
    sda_device_audience_data_s device_audience_data;
    sda_status_internal_e sda_audience_status;
    size_t audence_index = 0;
    CborParser parser;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    cbor_error = cbor_parser_init(audience_array_ptr, audience_array_size, 0, &parser, &audience_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)cbor_error);


    //Check audience array
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&audience_array) != CborArrayType), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), "Wrong type of audience_array");

    //Get and check audience array's length
    cbor_error = cbor_value_get_array_length(&audience_array, &audience_array_length);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), "Failed to get audience array size");
    SDA_ERR_RECOVERABLE_RETURN_IF((audience_array_length == 0), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), "Audience array size is wrong");

    memset(&device_audience_data, 0, sizeof(device_audience_data));

    //Read device audience data
    sda_status_internal = sda_device_audience_data_get(&device_audience_data);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = SDA_STATUS_INTERNAL_AUDIENCE_VERIFICATION_ERROR, "Failed to get device audience data");

    sda_audience_status = SDA_STATUS_INTERNAL_GENERAL_ERROR;

    //Start iterations on the audience array
    cbor_error = cbor_value_enter_container(&audience_array, &current_audience_data);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_value_enter_container for audience array failed");

    for (audence_index = 0; audence_index < audience_array_length; audence_index++) {

        //Initialize variables for the next iteration
        if ((cbor_error == CborNoError) && (cbor_value_is_text_string(&current_audience_data) == true)) {
            //get audience string data buffer and it size
            status = sda_get_data_buffer_from_cbor_tiny(&current_audience_data, &current_audience_buffer, &current_audience_buffer_size);

            //If we succeeded to get current audience buffer:
            if (status != false && current_audience_buffer != NULL && current_audience_buffer_size != 0) {
                //Get the audience data from the member
                sda_audience_status = sda_audience_data_get((const uint8_t*)current_audience_buffer, (size_t)current_audience_buffer_size, &audience_data);
                //In case known audience type not found do not return an error, keep looking for known types
                if (sda_audience_status == SDA_STATUS_INTERNAL_SUCCESS) {
                    //Check the retrieved request audience data against device corresponding data
                    sda_audience_status = sda_device_audience_verify(&audience_data, &device_audience_data);
                    if (sda_audience_status == SDA_STATUS_INTERNAL_SUCCESS) {
                        break;
                    }//sda_device_audience
                }
            }//sda_status == SDA_STATUS_SUCCESS
        }

         //Get next cbor  member of the array
        cbor_error = cbor_value_advance(&current_audience_data);
    }//for
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_audience_status != SDA_STATUS_INTERNAL_SUCCESS), SDA_STATUS_INTERNAL_AUDIENCE_VERIFICATION_ERROR, "Invalid audience data");

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;
}

sda_status_internal_e sda_token_expiration_verify(const cwt_claims_s *cwt_claims)
{
    uint64_t current_time = 0;
    uint64_t expiration_date;
    uint64_t not_before;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SDA_ERR_RECOVERABLE_RETURN_IF((cwt_claims == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Wrong cwt_claims pointer");
    expiration_date = cwt_claims->exp;
    not_before = cwt_claims->nbf;

    current_time = pal_osGetTime();

    //If the time is not set in the system , the function returns success
    if (current_time == 0) {
        return SDA_STATUS_INTERNAL_SUCCESS;
    }

    SDA_ERR_RECOVERABLE_RETURN_IF((expiration_date + SDA_GARCE_TIME_PERIOD < current_time), SDA_STATUS_INTERNAL_TOKEN_EXPIRATION_ERROR, "The token is expired");
    SDA_ERR_RECOVERABLE_RETURN_IF((not_before - SDA_GARCE_TIME_PERIOD > current_time), SDA_STATUS_INTERNAL_TOKEN_EXPIRATION_ERROR, "The token is still not valid");

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    return SDA_STATUS_INTERNAL_SUCCESS;
}


sda_status_internal_e sda_operation_bundle_verify(const sda_message_data_s *bundle_data)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    uint8_t raw_trust_anchor[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    size_t trust_anchor_size = 0;
    bool success;
    uint8_t *trust_anchor_name;
    size_t trust_anchor_name_size;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // Nonce value can't be zero
    SDA_ERR_RECOVERABLE_RETURN_IF((bundle_data->nonce == 0), SDA_STATUS_INTERNAL_NONCE_VERIFICATION_ERROR, "Got zero value for nonce");

    // Verify nonce value to prevent replay attacks
    success = sda_nonce_verify_and_delete(bundle_data->nonce);
    SDA_DEMO_CHECK_ERROR((!success), "Failed to validate nonce");
    SDA_ERR_RECOVERABLE_RETURN_IF((!success), SDA_STATUS_INTERNAL_NONCE_VERIFICATION_ERROR, "Failed to verify nonce");
    SDA_LOG_DEMO_INFO("Nonce verified successfully");

    //Check token expiration
    sda_status_internal = sda_token_expiration_verify(&bundle_data->claims);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal, "Failed to verify token expiration");

    // Now we validate the access token with server's pk that is stored in the KCM
    // The anchor name is located in the server's CWT, issuer field.
    trust_anchor_name = bundle_data->claims.issuer_data;
    trust_anchor_name_size = bundle_data->claims.issuer_data_size;
    sda_status_internal = sda_trust_anchor_get(trust_anchor_name, trust_anchor_name_size, raw_trust_anchor, sizeof(raw_trust_anchor), &trust_anchor_size);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal, "Failed to get Trust Anchor");

    //Validate access token signature against trust anchor public key
    sda_status_internal = sda_cose_validate_with_raw_pk(bundle_data->access_token.data_buffer_ptr, bundle_data->access_token.data_buffer_size, raw_trust_anchor, trust_anchor_size);
    SDA_DEMO_CHECK_ERROR((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), "Failed to validate Access Token");
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), SDA_STATUS_INTERNAL_TOKEN_VERIFICATION_ERROR, "Failed to validate Access Token");
    SDA_LOG_DEMO_INFO("Access Token verified successfully");

    // Now we validate the main operation bundle signature against POP public key from the access token
    sda_status_internal = sda_cose_validate_with_raw_pk(bundle_data->main_signed_operation_bundle.data_buffer_ptr, bundle_data->main_signed_operation_bundle.data_buffer_size, bundle_data->claims.pk, (bundle_data->claims).pk_size);
    SDA_DEMO_CHECK_ERROR((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), "Failed to validate Access Token");
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), SDA_STATUS_INTERNAL_OPERATION_VERIFICATION_ERROR, "Failed to validate Operation bundle");
    SDA_LOG_DEMO_INFO("Operation command bundle signature verified successfully");

    // Validate Audience
    sda_status_internal = sda_audience_verify_tiny(bundle_data->claims.audience_array_ptr, bundle_data->claims.audience_array_size);
    SDA_DEMO_CHECK_ERROR((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), "Failed to validate audience");
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal, "Failed to validate audience");
    SDA_LOG_DEMO_INFO("Audience verified successfully");

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;
}
