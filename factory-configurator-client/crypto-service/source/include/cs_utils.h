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

#ifndef __CS_UTILS_H__
#define __CS_UTILS_H__

#include <stdlib.h>
#include <stdbool.h>
#include "pal.h"
#include "kcm_status.h"


#ifdef __cplusplus
extern "C" {
#endif

/**Convert pal status to crypto service status
*
*@pal_status – pal status as returned from PAL API.
*
*@return
*    Status from  kcm_status_e corresponding to pal status.
*/
kcm_status_e cs_error_handler(palStatus_t pal_status);

/**Checks correlation between certificate's public key and private key
*
*@x509_cert[in] - handle of x509 certificate.
*@size_of_device_cert[in] - size of certificate data.
*@private_key_data[in] - pointer to private key der data.
*@size_of_private_key_data[in] - size of private key data.
*
*@return
*    Status from  kcm_status_e corresponding to pal status.
*/
kcm_status_e cs_check_certifcate_public_key(palX509Handle_t x509_cert,
    const uint8_t *private_key_data,
    size_t size_of_private_key_data);


#ifdef __cplusplus
}
#endif

#endif  //__CS_UTILS_H__
