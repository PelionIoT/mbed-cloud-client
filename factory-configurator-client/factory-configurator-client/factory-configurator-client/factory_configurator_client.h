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

#ifndef __FACTORY_CONFIGURATOR_CLIENT_H__
#define __FACTORY_CONFIGURATOR_CLIENT_H__

#include <stdlib.h>
#include <inttypes.h>
#include "fcc_status.h"
#include "fcc_output_info_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @file factory_configurator_client.h
*  \brief factory configurator client APIs.
*/

/* === Initialization and Finalization === */

/** Initiates the FCC module. Must be called before any other fcc's APIs. Otherwise relevant error will be returned.
*
*   @returns
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_init(void);


/** Finalizes the FCC module.
*   Finalizes and frees file storage resources.
*
*    @returns
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/

fcc_status_e fcc_finalize(void);

/* === Factory clean operation === */

/** Cleans from the device all data that was saved during the factory process.
*  Should be called if the process failed and needs to be executed again.
*
*   @returns
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_storage_delete(void);


/* === Warning and errors data operations === */

/** The function retrieves pointer to warning and errors structure.
*  Should be called after fcc_verify_device_configured_4mbed_cloud, when possible warning and errors was
*  stored in the structure.
*  The structure contains data of last fcc_verify_device_configured_4mbed_cloud run.*
*   @returns pointer to fcc_output_info_s structure.
*
*  Example:
*  @code
*  void print_fcc_output_info(fcc_output_info_s *output_info)
*  {
*      fcc_warning_info_s *warning_list = NULL;
*
*      if (output_info != NULL) {
*          // Check if there is an error
*          if (output_info->error_string_info != NULL) {
*              // Print the error string
*              printf("fcc output error: %s", output_info->error_string_info);
*          }
*          // Check if there are warnings
*          if (output_info->size_of_warning_info_list > 0) {
*              // Set warning_list to point on the head of the list
*              warning_list = output_info->head_of_warning_list;
*
*              // Iterate the list
*              while (warning_list != NULL) {
*                  // Print the warning string
*                  printf("fcc output warning: %s", warning_list->warning_info_string);
*                  // Move warning_list to point on the next warning in he list
*                  warning_list = warning_list->next;
*              }
*          }
*      }
*  }
*  @endcode
*
*/
fcc_output_info_s* fcc_get_error_and_warning_data(void);

/** The function returns status of current session between the FCC and the FCU.
* If the returned value is true - the session should be finished in the communication layer after current message processing,
* if the return value is false - the session should be kept alive for next message.
*
*    @returns
*       bool
*/
bool fcc_is_session_finished(void);

/* === Verification === */

/** Verifies that all mandatory fields needed to connect to mbed Cloud are in place on the device.
 *  Should be called in the end of the factory process
 *
 *    @returns
 *       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
 */
fcc_status_e fcc_verify_device_configured_4mbed_cloud(void);


/* === Secure Time === */

/** Sets device time. This function will set the device time to what the user provides.
*   Device time must be set in order to enable certificate expiration validations.
*
*     @param time The device time to set. As epoch time (number of seconds that have elapsed since January 1, 1970)
*
*     @returns
*        Operation status.
*/
fcc_status_e fcc_time_set(uint64_t time);


/* === Entropy and RoT injection === */

/** Sets Entropy.
*   If  device does not have its own entropy - this function must be called after fcc_init() and prior to any other FCC or KCM functions.
*   This API should be used if device has its own entropy and user wishes to add his own entropy.
*
*     @param buf The buffer containing the entropy.
*     @param buf_size The size of buf in bytes. Must be exactly FCC_ENTROPY_SIZE.
*
*     @returns
*        Operation status.
*/
fcc_status_e fcc_entropy_set(const uint8_t *buf, size_t buf_size);

/** Sets root of trust
*   If user wishes to set his own root of trust, this function must be called after fcc_init() and fcc_entropy_set() (if user sets his own entropy),
*   and prior to any other FCC or KCM functions.
*
*     @param buf The buffer containing the root of trust.
*     @param buf_size The size of buf in bytes. Must be exactly FCC_ROT_SIZE.
*
*     @returns
*        Operation status.
*/
fcc_status_e fcc_rot_set(const uint8_t *buf, size_t buf_size);

/* === Bootstrap CA certificate identification storage === */

/** The function sets bootstrap ca identification and stores it.
*   Should be called only after storing bootstrap ca certificate on the device.
*
*     @returns
*        Operation status.
*/
fcc_status_e fcc_trust_ca_cert_id_set(void);


/* === Factory flow disable === */
/** Sets Factory disabled flag to disable further use of the factory flow.
*
*     @returns
*        Operation status.
*/
fcc_status_e fcc_factory_disable(void);

/** Returns true if the factory flow was disabled by calling fcc_factory_disable() API, outherwise
*   returns false.
*
*   - If the factory flow is already disabled any FCC API(s) will fail.
*
*     @param fcc_factory_disable An output parameter, will be set to "true" in case factory
*                                     flow is already disabled, "false" otherwise.
*
*   @returns
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_is_factory_disabled(bool *fcc_factory_disable);

/* === Developer flow === */

/** This API is for developers only.
*   You can download the `mbed_cloud_dev_credentials.c` file from the portal and thus, skip running FCU on PC side.
*   The API reads all credentials from the `mbed_cloud_dev_credentials.c` file and stores them in the KCM.
*   RoT, Entropy and Time configurations are not a part of fcc_developer_flow() API. Devices that need to set RoT or Entropy
*   should call `fcc_rot_set()`/`fcc_entropy_set()` APIs before fcc_developer_flow().
*   If device does not have it's own time configuration and `fcc_time_set()` was not called before  fcc_developer_flow(),
*   during fcc_verify_device_configured_4mbed_cloud() certificate time validity will not be checked.
*
*
*   @returns
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_developer_flow(void);


#ifdef __cplusplus
}
#endif

#endif //__FACTORY_CONFIGURATOR_CLIENT_H__
