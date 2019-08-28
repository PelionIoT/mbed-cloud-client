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

#include "sda_trust_anchor.h"
#include "sda_status.h"
#include "sda_error_handling.h"
#include "key_config_manager.h"
#include <stdint.h> 

#include "cs_der_keys_and_csrs.h"


sda_status_internal_e sda_trust_anchor_get(const uint8_t *trust_anchor_key_name, size_t trust_anchor_key_name_size,
    uint8_t *trust_anchor_key_out, size_t trust_anchor_key_buffer_size, size_t *trust_anchor_key_size_out)
{
    kcm_status_e kcm_status;
    uint8_t der_trust_anchor[SDA_TRUST_ANCHOR_SIZE] = { 0 };
    size_t der_trust_anchor_size_out = 0;

    SDA_LOG_TRACE_FUNC_ENTER("trust_anchor_key_name_size = %" PRIu32 " trust_anchor_key_buffer_size = %" PRIu32 "", (uint32_t)trust_anchor_key_name_size, (uint32_t)trust_anchor_key_buffer_size);

    SDA_ERR_RECOVERABLE_RETURN_IF((trust_anchor_key_name == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid Trust Anchor key name");
    SDA_ERR_RECOVERABLE_RETURN_IF((trust_anchor_key_name_size == 0), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid Trust Anchor key name size");
    SDA_ERR_RECOVERABLE_RETURN_IF((trust_anchor_key_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid Trust Anchor buffer");
    SDA_ERR_RECOVERABLE_RETURN_IF((trust_anchor_key_size_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid size pointer");
    SDA_ERR_RECOVERABLE_RETURN_IF((trust_anchor_key_buffer_size < KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Insufficient buffer");

    //Get trust anchor in DER format
    kcm_status = kcm_item_get_data(trust_anchor_key_name, trust_anchor_key_name_size, KCM_PUBLIC_KEY_ITEM, der_trust_anchor, sizeof(der_trust_anchor), &der_trust_anchor_size_out);
    SDA_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), SDA_STATUS_INTERNAL_TRUST_ANCHOR_NOT_FOUND, "Trust anchor not found (%.*s)", (int)trust_anchor_key_name_size, trust_anchor_key_name);
    SDA_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), SDA_STATUS_INTERNAL_KCM_ERROR, "KCM get failed. KCM status %d", kcm_status);
    SDA_ERR_RECOVERABLE_RETURN_IF((der_trust_anchor_size_out != SDA_TRUST_ANCHOR_SIZE), SDA_STATUS_INTERNAL_KCM_ERROR, "Wrong size of der_trust_anchor_size_out ");

    //Get raw trust anchor
    kcm_status = cs_pub_key_get_der_to_raw(der_trust_anchor, der_trust_anchor_size_out, trust_anchor_key_out, trust_anchor_key_buffer_size, trust_anchor_key_size_out);
    SDA_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), SDA_STATUS_INTERNAL_EXPORT_FROM_DER_TRUST_ANCHOR_ERROR, "Failed to get raw trust anchor");


    SDA_LOG_TRACE_FUNC_EXIT("trust_anchor_key_size_out = %" PRIu32, (uint32_t)*trust_anchor_key_size_out);
    return SDA_STATUS_INTERNAL_SUCCESS;
}
