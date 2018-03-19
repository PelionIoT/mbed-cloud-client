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

#ifndef __FCC_SOTP_H__
#define __FCC_SOTP_H__

#include "factory_configurator_client.h"
#include "sotp.h"

#ifdef __cplusplus
extern "C" {
#endif


// Size of factory disabled flag in SOTP - internal use only.
#define FCC_FACTORY_DISABLE_FLAG_SIZE    sizeof(int64_t)
/** Writes data to SOTP
*
* @param data[in]         The data to store in SOTP.
* @param data_size[in]     The size of buf in bytes. Must be divisible by 8, and less than or equal to 1024. Must be according to sotp_type.
* @param sotp_type[in]    Enum representing the type of the item to be stored in SOTP.
*
* @return
*     FCC_STATUS_SUCCESS for success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_sotp_data_store(const uint8_t *data, size_t data_size, sotp_type_e sotp_type);

/** Reads data from SOTP
*
* @param data_out[out]             A buffer to retrieve data from SOTP.
* @param data_size_max[in]         The size of data_out max. bytes.
* @param data_actual_size_out[out] The actual size of bytes returned by this function, should be less or equal to data_size_max.
* @param sotp_type[in]             Enum representing the type of the item to be stored in SOTP.
*
* @return
*     FCC_STATUS_SUCCESS for success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_sotp_data_retrieve(uint8_t *data_out, size_t data_size_max, size_t *data_actual_size_out, sotp_type_e sotp_type);


#define MAX_SOTP_BUFFER_SIZE    FCC_ENTROPY_SIZE

#ifdef __cplusplus
}
#endif

#endif //__FCC_SOTP_H__
