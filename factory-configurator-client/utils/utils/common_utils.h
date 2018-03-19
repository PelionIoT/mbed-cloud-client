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

#ifndef __COMMON_UTILS_H__
#define __COMMON_UTILS_H__

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

/**This function retrieves kcm data buffer and its size according to the given name.
* In case of success - The function allocates buffer for current kcm data and it is a user's responsibility to free the allocated memory.
*
* @param parameter_name[in]                  buffer of parameter name.
* @param size_of_parameter_name[in]          size of parameter name.
* @kcm_type[in]                              type of kcm data to retrieve
* @param kcm_data[out]                       pointer to kcm data.
* @param kcm_data_size[out]                  size of kcm data.
*        fcc_status_e status.
*/
fcc_status_e fcc_get_kcm_data(const uint8_t *parameter_name, size_t size_of_parameter_name, kcm_item_type_e kcm_type, uint8_t **kcm_data, size_t *kcm_data_size);
#if 0
/**This function retrieves certificate's attribute using it's name.
* The function allocates memory for attribute data buffer  and it is user's responsibility to free the allocated  memory.
*
* @param cert_name[in]                  The name of certificate
* @param size_of_cert_name[in]          The size of certificate name.
* @param attribute_type[in]             The type of attribute to retrieve.
* @param attribute_data[out]            Attribute data buffer. If NULL and the size of the attribute_data_size is 0,the buffer is allocated by the function.
*                                       Otherwise the function uses supplied buffer.
* @param attribute_act_data_size[out]   The actual size of attribute data buffer.
*        fcc_status_e status.
*/
fcc_status_e fcc_get_certificate_attribute_by_name_with_allocate(const uint8_t *cert_name, size_t size_of_cert_name, cs_certificate_attribute_type_e attribute_type, uint8_t **attribute_data, size_t attribute_data_size, size_t *attribute_act_data_size);
#endif
/**This function retrieves certificate's attribute using it's name.
* The function allocates memory for attribute data buffer in case it was not allocated by user, and it is user's responsibility to free the allocated  memory.
* @param cert_name[in]                  The name of certificate
* @param size_of_cert_name[in]          The size of certificate name.
* @param attribute_type[in]             The type of attribute to retrieve.
* @param attribute_data[out]            Attribute data buffer. If NULL and the size of the attribute_data_size is 0,the buffer is allocated by the function.
*                                       Otherwise the function uses supplied buffer.
* @param attribute_data_size[in]       Attribute data buffer. Should be 0 in case the attribute_data is NULL.
* @param attribute_act_data_size[out]   The actual size of attribute data buffer.
*        fcc_status_e status.
*/
fcc_status_e fcc_get_certificate_attribute_by_name(const uint8_t *cert_name, size_t size_of_cert_name, cs_certificate_attribute_type_e attribute_type, uint8_t *attribute_data, size_t attribute_data_size, size_t *attribute_act_data_size);


/**This function retrieves certificate's attribute and it's size according to its type.
*   The function allocates memory for the attribute and it is a user's responsibility to free the allocated memory.
*
* @param certificate_data[in]                  buffer of certificate.
* @param size_of_certificate_data[in]          size of certificate data.
* @attribute_type[in]                          type of attribute to retrieve.
* @param attribute_data[out]                   attribute data buffer.
* @param attribute_act_data_size[out]          actual size of the attribute data
*        fcc_status_e status.
*/
fcc_status_e fcc_get_certificate_attribute(palX509Handle_t x509_cert, cs_certificate_attribute_type_e attribute_type, uint8_t **attribute_data, size_t *attribute_act_data_size);


#ifdef __cplusplus
}
#endif

#endif //__COMMON_UTILS_H__
