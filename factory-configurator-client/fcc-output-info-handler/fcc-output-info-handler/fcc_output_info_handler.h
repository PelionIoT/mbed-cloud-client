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

#ifndef __FCC_OUTPUT_INFO_HANDLER_H__
#define __FCC_OUTPUT_INFO_HANDLER_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include  "kcm_status.h"
#include "fcc_output_info_handler_defines.h"
#include "fcc_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
*   Initializes resources of output info handler
*/
void  fcc_init_output_info_handler( void );

/**
*  Finalizes resources of output info handler
*/
void  fcc_clean_output_info_handler( void );

/**
*  Returns true if FCC was initialized false otherwise
*/
bool is_fcc_initialized(void);

/**  The function stores the name of failed item and kcm error string in global variables
* The error returned by fcc_bundle_handler API.
*
* @param failed_item_name[in]          The name of failed item 
* @param failed_item_name_size[in]     The size of failed item name.
* @param kcm_status[in]                The kcm status value.
*
* @return
*     true for success, false otherwise.
*/
fcc_status_e fcc_bundle_store_error_info(const uint8_t *failed_item_name, size_t failed_item_name_size, kcm_status_e kcm_status);

/**  The function stores the name of failed item and fcc error string in global variables
*The error returned by fcc_verify_device_configured_4mbed_cloud API.

* @param failed_item_name[in]          The name of failed item. If NULL, error will be stored without an item name.
* @param failed_item_name_size[in]     The size of failed item name.
* @param fcc_status[in]               The fcc status value.
*
* @return
*     true for success, false otherwise.
*/
fcc_status_e fcc_store_error_info(const uint8_t *failed_item_name, size_t failed_item_name_size, fcc_status_e fcc_status);

/**  The function stores the all collected warnings and relevant item names during fcc_verify_device_configured_4mbed_cloud API.
*
* @param failed_item_name[in]          The name of failed item
* @param failed_item_name_size[in]     The size of failed item name.
* @param fcc_status[in]               The fcc status value.
*
* @return
*     true for success, false otherwise.
*/
fcc_status_e fcc_store_warning_info(const uint8_t *failed_item_name, size_t failed_item_name_size, const char *warning_string);
/**  The function return saved failed item name
*
* @return
*     NULL if no errors or char* pointer to the saved item name
*/
char* fcc_get_output_error_info( void );
/**  The function return saved warnings as single string
*
* @return
*     NULL  if no warnings exist or char* pointer to the string of all warnings
*/
char*  fcc_get_output_warning_info(void);

/**  The function returns relevant pointer to string of passed fcc_status.
*
* @return
*     string /NULL in case the fcc_status string wasn't found
*/
char* fcc_get_fcc_error_string(fcc_status_e fcc_status);

/**  The function returns relevant pointer to string of passed kcm_status.
*
* @return
*     string /NULL in case the kcm_status string wasn't found
*/
char* fcc_get_kcm_error_string(kcm_status_e kcm_status);

/**  The function gets output info structure
*
* @return
*/
fcc_output_info_s* get_output_info(void);

/**  The function gets status of warning info
*
* @return
*    true - if warnings were stored, false in case of no warning
*/
bool fcc_get_warning_status(void);

#ifdef __cplusplus
}
#endif

#endif //__FCC_OUTPUT_INFO_HANDLER_H__
