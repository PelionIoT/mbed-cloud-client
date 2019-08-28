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

#ifndef __SDA_ERROR_TRANSLATION_H__
#define __SDA_ERROR_TRANSLATION_H__

#include "cs_der_keys_and_csrs.h"
#include "sda_data_token.h"
/**
* @file sda_defs.h
*  \brief device based authorization defines.
*
*/

#ifdef __cplusplus
extern "C" {
#endif



/** The function converts internal status to appropriate sda error.
*
* @param internal_status The value of internal status.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_e sda_return_status_translate(sda_status_internal_e internal_status);

#ifdef __cplusplus
}
#endif

#endif //__SDA_ERROR_TRANSLATION_H__
