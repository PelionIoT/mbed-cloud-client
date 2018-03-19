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

#include "pv_error_handling.h"
#include "cs_hash.h"
#include "pal_Crypto.h"
#include "cs_utils.h"

kcm_status_e cs_hash(cs_hash_mode_e mode, const uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size)
{
    palStatus_t pal_status = PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid data pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((digest == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid digest pointer");
  
    switch (mode) {
        case CS_SHA256:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((digest_size != CS_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid digest size");
            pal_status = pal_sha256(data, data_size, digest);
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE, "Hash mode not supported");
    }

    return cs_error_handler(pal_status);
}
