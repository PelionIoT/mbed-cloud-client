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

#ifndef __FCC_UTILS_H__
#define __FCC_UTILS_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "key_config_manager.h"
#include "factory_configurator_client.h"
#include "fcc_defs.h"
#include "fcc_sotp.h"

#ifdef __cplusplus
extern "C" {
#endif


extern const char g_sotp_entropy_data_type_name[];
extern const char g_sotp_rot_data_type_name[];
extern const char g_sotp_factory_disable_type_name[];
extern const char g_sotp_ca_server_id_type_name[];
extern const char g_sotp_time_type_name[];

/** Returns sotp type name and name size
*
* @param sotp_type[in]             The sotp type
* @param sotp_type_name[out]       The pointer to sotp type name
* @param sotp_type[out]            The size of sotp type name
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_get_sotp_type_name(sotp_type_e sotp_type, char* *sotp_type_name, size_t *sotp_type_name_size);

/** Converts kcm error status to appropriate fcc error.
*
* @param kcm_result[in/out]    The kcm error status
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_convert_kcm_to_fcc_status(kcm_status_e kcm_result);

#ifdef __cplusplus
}
#endif

#endif //__FCC_UTILS_H__
