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

#ifndef __FCC_VERIFICATION_H__
#define __FCC_VERIFICATION_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "key_config_manager.h"
#include "factory_configurator_client.h"
#include "fcc_defs.h"
#include "cs_utils.h"
#include "cs_der_certs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* The size of the binary representation of UUID5. Used in verifying firmware vendor and class IDs.
*/
#define FCC_UUID5_SIZE_IN_BYTES 16

/**
* Types of configuration parameter
*/
typedef enum {
    FCC_MANUFACTURER_NAME_CONFIG_PARAM_TYPE,
    FCC_MODEL_NUMBER_CONFIG_PARAM_TYPE,
    FCC_DEVICE_TYPE_CONFIG_PARAM_TYPE,
    FCC_HARDWARE_VERSION_CONFIG_PARAM_TYPE,
    FCC_MEMORY_TOTAL_SIZE_CONFIG_PARAM_TYPE,
    FCC_DEVICE_SERIAL_NUMBER_CONFIG_PARAM_TYPE,
    FCC_MAX_CONFIG_PARAM_TYPE
} fcc_config_param_type_e;

/**
* Configuration parameters lookup record, correlating parameter's type and name
*/
typedef struct fcc_config_param_lookup_record_ {
    fcc_config_param_type_e config_param_type;
    const char *config_param_name;
} fcc_config_param_lookup_record_s;


/** Checks entropy initialization
*
*    @returns
*        entropy status  true/false.
*/
bool fcc_is_entropy_initialized(void);

/** Checks that all mandatory device meta data is present
*
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_check_device_meta_data(void);

/** Gets current bootstrap mode
*
* @param use_bootstrap[in/out]    The bootstrap mode
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_get_bootstrap_mode(bool *use_bootstrap);

/**Function that checks all time synchronization parameters.
*
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_check_time_synchronization(void);

/** Checks mandatory device general info  - endpoint name. Does not check bootstrap_mode (checked with fcc_get_bootstrap_mode()).
*
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_check_device_general_info( void );

/** Checks device security objects : root ca certificate, device certificate, device private key and server URL.
*
* @param device_objects[in]           Structure with set of device security object names.
* @param use_bootstrap[in]         Bootstrap mode.
*    @returns
*        fcc_status_e status.
*/
fcc_status_e fcc_check_device_security_objects(bool use_bootstrap);


/** Checks firmware update integrity objects
*
*    @returns
*        fcc_status_e status.
*/
fcc_status_e  fcc_check_firmware_update_integrity( void );


#ifdef __cplusplus
}
#endif

#endif //__FCC_VERIFICATION_H__
