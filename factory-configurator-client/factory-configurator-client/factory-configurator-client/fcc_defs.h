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

#ifndef __FCC_DEFS_H__
#define __FCC_DEFS_H__


#ifdef __cplusplus
extern "C" {
#endif
/**
* @file fcc_defs.h
*  \brief factory configurator client defines.
* Contains the names of all parameters needed to configure the device to work with mbed Cloud.
*/
/*
* Warnings linked list structure
*/
struct fcc_warning_info_ {
    //Example for warning_info_string - "Certificate is self signed:mbed.BootstrapServerCACert"
    char *warning_info_string;// pattern of the warning string - warning_string:item_name
    struct fcc_warning_info_ *next;
};
typedef struct fcc_warning_info_ fcc_warning_info_s;
/**
* Output info structure
*/
typedef struct fcc_output_info_ {
    //Example for error_string_info - "Invalid certificate:mbed.BootstrapServerCACert"
    char *error_string_info; // pattern of the error string - error_string:failed_item_name. Only one error string is possible.
    size_t size_of_warning_info_list; // size of warning_info_list
    struct fcc_warning_info_ *head_of_warning_list; //The head of warning list
    struct fcc_warning_info_ *tail_of_warning_list; //The tail of warning list
} fcc_output_info_s;
/*=== Device general information ===*/

/**
* Bootstrap mode parameter name.
*/
extern const char g_fcc_use_bootstrap_parameter_name[];

/**
* Endpoint parameter name.
*/
extern const char g_fcc_endpoint_parameter_name[];

/**
* First to claim parameter name.
*/
extern const char g_fcc_first_to_claim_parameter_name[];

/*=== Device meta data ===*/

/**
* Manufacturer parameter name.
*/
extern const char g_fcc_manufacturer_parameter_name[];

/**
* Model number parameter name.
*/
extern const char g_fcc_model_number_parameter_name[];

/**
* Device type parameter name.
*/
extern const char g_fcc_device_type_parameter_name[];

/**
* Hardware version parameter name.
*/
extern const char g_fcc_hardware_version_parameter_name[];

/**
* Memory size parameter name.
*/
extern const char g_fcc_memory_size_parameter_name[];

/**
* Device serial number parameter name.
*/
extern const char g_fcc_device_serial_number_parameter_name[];

/**
* Device current time parameter name.
*/
extern const char g_fcc_current_time_parameter_name[];
/**
* Device time zone name.
*/
extern const  char g_fcc_device_time_zone_parameter_name[];
/**
* Offset of the device timezone from UTC name.
*/
extern const char g_fcc_offset_from_utc_parameter_name[];

/*=== Bootstrap configuration ===*/

/**
* Bootstrap server CA certificate parameter name.
*/
extern const char g_fcc_bootstrap_server_ca_certificate_name[];

/**
* Bootstrap server CRL parameter name.
*/
extern const char g_fcc_bootstrap_server_crl_name[];

/**
* Bootstrap server URI parameter name.
*/
extern const char g_fcc_bootstrap_server_uri_name[];

/**
* Bootstrap device certificate parameter name.
*/
extern const char g_fcc_bootstrap_device_certificate_name[];

/**
* Bootstrap device private key parameter name.
*/
extern const char g_fcc_bootstrap_device_private_key_name[];

/*=== LWM2M configuration ===*/

/**
* LWM2M server CA certificate parameter name.
*/
extern const char g_fcc_lwm2m_server_ca_certificate_name[];

/**
* LWM2M server CRL parameter name.
*/
extern const char g_fcc_lwm2m_server_crl_name[];

/**
* LWM2M server URI parameter name.
*/
extern const char g_fcc_lwm2m_server_uri_name[];

/**
* LWM2M device certificate parameter name.
*/
extern const char g_fcc_lwm2m_device_certificate_name[];

/**
* LWM2M device private key parameter name.
*/
extern const char g_fcc_lwm2m_device_private_key_name[];

/**
* Firmware update authentication certificate parameter name.
*/
extern const char g_fcc_update_authentication_certificate_name[];


/**
* Firmware update class id name.
*/
extern const char g_fcc_class_id_name[];

/**
* Firmware update vendor id name.
*/

extern const char g_fcc_vendor_id_name[];

#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
extern const char g_fcc_mbed_internal_endpoint[];
extern const char g_fcc_account_id[];
#endif

#ifdef __cplusplus
}
#endif

#endif //__FCC_DEFS_H__
