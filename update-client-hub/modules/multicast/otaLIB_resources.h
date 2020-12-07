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
#include "mbed-client/m2mconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

// OTA lwm2m resources
#define ota_resource_dodag_id              "33458/0/0"
#define ota_resource_connected_nodes       "33458/0/1"
#define ota_resource_ready_for_multicast   "33458/0/2"
#define ota_resource_status                "33458/0/3"
#define ota_resource_session               "33458/0/4"
#define ota_resource_command               "33458/0/5"
#define ota_resource_estimated_total_time  "33458/0/6"
#define ota_resource_estimated_resend_time "33458/0/7"
#define ota_resource_error                 "33458/0/8"
#define ota_resource_fragment_size         "33458/0/9"

// Resource callback functions
uint8_t ota_lwm2m_command(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
uint8_t ota_fragment_size_command(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);

#ifdef RESOURCE_ATTRIBUTES_LIST
sn_nsdl_attribute_item_s default_attributes[2] = {
        {ATTR_RESOURCE_TYPE, OMA_RESOURCE_TYPE},
        {ATTR_END, 0}
};
#endif

// Multicast network identifier <0>
static sn_nsdl_static_resource_parameters_s ota_dodag_id_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Netid",              // resource_type_ptr
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
    NULL,
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

// Number of connected nodes <1>
static sn_nsdl_static_resource_parameters_s ota_connected_nodes_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Connected Nodes",           // resource_type_ptr
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
    NULL,
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

// OTA ready for multicast <2>
static sn_nsdl_static_resource_parameters_s ota_ready_for_multicast_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Session Ready",           // resource_type_ptr
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
    NULL,
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

// Multicast status <3>
static sn_nsdl_static_resource_parameters_s ota_status_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Status",  // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_status, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_status_dyn_params = {
    NULL,
    &ota_status_static_params,
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

// Multicast session id <4>
static sn_nsdl_static_resource_parameters_s ota_session_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Session ID",  // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_session, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_session_dyn_params = {
    NULL,
    &ota_session_static_params,
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

// Multicast command <5>
static sn_nsdl_static_resource_parameters_s ota_command_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Command",         // resource_type_ptr
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
    SN_GRS_POST_ALLOWED,    // access
    0,                                          // registered
    true,                                       // publish_uri
    false,                                      // free_on_delete
    false,                                      // observable
    false,                                      // auto-observable
    false,                                      // always_publish
    0,                                          // publish_value
};

// Multicast estimated total time <6>
static sn_nsdl_static_resource_parameters_s ota_estimated_total_time_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Estimated Total Time", // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_estimated_total_time, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_estimated_total_time_dyn_params = {
    NULL,
    &ota_estimated_total_time_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    true,                  // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value
};

// Multicast estimated resend time <7>
static sn_nsdl_static_resource_parameters_s ota_estimated_resend_time_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Estimated Resend Time", // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_estimated_resend_time, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_estimated_resend_time_dyn_params = {
    NULL,
    &ota_estimated_resend_time_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    true,                  // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value
};

// Multicast error <8>
static sn_nsdl_static_resource_parameters_s ota_error_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Error", // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_error, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_error_dyn_params = {
    NULL,
    &ota_error_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED,     // access
    0,                      // registered
    true,                   // publish_uri
    false,                  // free_on_delete
    true,                  // observable
    false,                  // auto-observable
    false,                  // always_publish
    0                       // publish_value
};

// Multicast fragment size <9>
static sn_nsdl_static_resource_parameters_s ota_fragment_size_static_params = {
    #ifndef RESOURCE_ATTRIBUTES_LIST
    #ifndef DISABLE_RESOURCE_TYPE
        (char*)"Multicast Fragment Size", // resource_type_ptr
    #endif
    #ifndef DISABLE_INTERFACE_DESCRIPTION
        (char*)"",                          // interface_description_ptr
    #endif
    #else
        default_attributes,
    #endif
        (char*)ota_resource_fragment_size, // path
        false,                              // external_memory_block
        SN_GRS_DYNAMIC,                     // mode
        false                               // free_on_delete
};

static sn_nsdl_dynamic_resource_parameters_s ota_fragment_size_dyn_params = {
    ota_fragment_size_command,
    &ota_fragment_size_static_params,
    NULL,
    {NULL, NULL},           // link
    0,
    0,                      // coap_content_type
    SN_GRS_GET_ALLOWED | SN_GRS_PUT_ALLOWED,     // access
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
