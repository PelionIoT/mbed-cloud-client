// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef OTALIB_RESOURCES_H_
#define OTALIB_RESOURCES_H_

#include "sn_nsdl_lib.h"

#ifdef __cplusplus
extern "C" {
#endif

// OTA lwm2m resources
#define ota_resource_connected_nodes       "26241/0/1"
#define ota_resource_ready_for_multicast   "26241/0/2"
#define ota_resource_command               "26241/0/3"
#define ota_resource_command_status        "26241/0/4"
#define ota_resource_dl_status             "26241/0/5"
#define ota_resource_expiration_time       "26241/0/6"
#define ota_resource_dodag_id              "26241/0/7"

// Resource callback functions
uint8_t ota_lwm2m_connected_nodes(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_ready_for_multicast(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_command(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_command_status(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_dl_status(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_expiration_time(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_lwm2m_dodag_id(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);

#ifdef RESOURCE_ATTRIBUTES_LIST
sn_nsdl_attribute_item_s default_attributes[2] = {
        {ATTR_RESOURCE_TYPE, OMA_RESOURCE_TYPE},
        {ATTR_END, 0}
};
#endif

// Number of connected nodes
static sn_nsdl_static_resource_parameters_s ota_connected_nodes_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",           // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_connected_nodes, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_connected_nodes_dyn_params = {
    ota_lwm2m_connected_nodes,
    &ota_connected_nodes_static_params,
    NULL,
    {NULL, NULL},                               // link
    0,
    0, // coap_content_type
    SN_GRS_GET_ALLOWED,                         // access
    0,                                          // registered
    true,                                       // publish_uri
    false,                                      // free_on_delete
    true,                                       // observable
    false,                                      // auto-observable
    false,                                      // always_publish
    0,                                          // publish_value
};

// OTA ready for multicast
static sn_nsdl_static_resource_parameters_s ota_ready_for_multicast_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",           // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_ready_for_multicast, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_ready_for_multicast_dyn_params = {
    ota_lwm2m_ready_for_multicast,
    &ota_ready_for_multicast_static_params,
    NULL,
    {NULL, NULL},                               // link
    0,
    0, // coap_content_type
    SN_GRS_GET_ALLOWED,                         // access
    0,                                          // registered
    true,                                       // publish_uri
    false,                                      // free_on_delete
    true,                                       // observable
    false,                                      // auto-observable
    false,                                      // always_publish
    0,                                          // publish_value
};

// OTA command data
static sn_nsdl_static_resource_parameters_s ota_command_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",         // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_command,       // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_command_dyn_params = {
    ota_lwm2m_command,
    &ota_command_static_params,
    NULL,
    {NULL, NULL},                               // link
    0,
    0, // coap_content_type
    SN_GRS_GET_ALLOWED | SN_GRS_PUT_ALLOWED,    // access
    0,                                          // registered
    true,                                       // publish_uri
    false,                                      // free_on_delete
    false,                                      // observable
    false,                                      // auto-observable
    false,                                      // always_publish
    0,                                          // publish_value
};

// Multicast command status
static sn_nsdl_static_resource_parameters_s ota_cmd_notify_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",  // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_command_status, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_cmd_notify_dyn_params = {
    ota_lwm2m_command_status,
    &ota_cmd_notify_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    true,                   // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value

};

// OTA download status
static sn_nsdl_static_resource_parameters_s ota_dl_status_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",     // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                              // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_dl_status,         // path
        false,                                  // external_memory_block
        SN_GRS_DYNAMIC,                         // mode
        false                                   // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_dl_status_dyn_params = {
    ota_lwm2m_dl_status,
    &ota_dl_status_static_params,
    NULL,
    {NULL, NULL},               // link
    0,
    0,                          // coap_content_type
    SN_GRS_GET_ALLOWED,         // access
    0,                          // registered
    true,                       // publish_uri
    false,                      // free_on_delete
    true,                       // observable
    false,                      // auto-observable
    false,                      // always_publish
    0                           // publish_value
};

// Multicast expiration time
static sn_nsdl_static_resource_parameters_s ota_expiration_time_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"", // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_expiration_time, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_expiration_time_dyn_params = {
    ota_lwm2m_expiration_time,
    &ota_expiration_time_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    false,                  // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value
};

// Multicast network identifier
static sn_nsdl_static_resource_parameters_s ota_dodag_id_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"",              // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_dodag_id,      // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};


static sn_nsdl_dynamic_resource_parameters_s ota_dodag_id_dyn_params = {
    ota_lwm2m_dodag_id,
    &ota_dodag_id_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    false,                  // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value
};

#ifdef __cplusplus
}
#endif

#endif // OTALIB_RESOURCES_H_
