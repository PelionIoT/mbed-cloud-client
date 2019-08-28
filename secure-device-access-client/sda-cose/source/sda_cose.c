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

#include "sda_cose.h"
#include "cose.h"
#include "sda_error_handling.h"
#include <inttypes.h>

sda_status_internal_e sda_cose_validate_with_raw_pk(const uint8_t *cose_msg, size_t cose_msg_size, const uint8_t *pKey, size_t keySize)
{
    bool status = true;
    cose_errback cose_error;
    HCOSE_SIGN0 hSign = NULL;
    int type;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SDA_ERR_RECOVERABLE_RETURN_IF((cose_msg == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid cose message buffer");
    SDA_ERR_RECOVERABLE_RETURN_IF((pKey == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid pKey buffer");

    hSign = (HCOSE_SIGN0)COSE_Init_tiny(cose_msg, cose_msg_size, &type, COSE_sign0_object, &cose_error);
    SDA_ERR_RECOVERABLE_RETURN_IF((!hSign), SDA_STATUS_INTERNAL_COSE_PARSING_ERROR, "COSE_Init failed");

    // Does NULL check for pKey
    status = COSE_Sign0_validate_with_raw_pk_tiny(hSign, pKey, keySize, &cose_error);
    SDA_ERR_RECOVERABLE_GOTO_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_VERIFICATION_ERROR, Exit, "COSE validation failed");

Exit:
    COSE_Sign0_Free(hSign );
    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;
}
