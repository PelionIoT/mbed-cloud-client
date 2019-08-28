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
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

fcc_status_e fcc_convert_kcm_to_fcc_status(kcm_status_e kcm_result);

fcc_status_e fcc_convert_pal_to_fcc_status(palStatus_t pal_result);

bool fcc_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif //__FCC_UTILS_H__
