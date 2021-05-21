/*
 * Copyright (c) 2011-2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * \file sn_nsdl.c
 *
 * \brief Nano service device library
 *
 */

// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "ns_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "source/include/sn_coap_protocol_internal.h"
#include "sn_nsdl_lib.h"
#include "sn_grs.h"
#include "mbed-trace/mbed_trace.h"
#include "mbedtls/base64.h"
#include "common_functions.h"
#include "mbed-client/m2mconfig.h"
#include "randLIB.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if defined MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#define MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#endif

/* Defines */
#define TRACE_GROUP "COAP"
#define RESOURCE_DIR_LEN                2
#define EP_NAME_PARAMETERS_LEN          3
#define ET_PARAMETER_LEN                3
#define LT_PARAMETER_LEN                3
#define VERSION_PARAMETER_LEN           6
#define DOMAIN_PARAMETER_LEN            2
#define RT_PARAMETER_LEN                3
#define IF_PARAMETER_LEN                3
#define NAME_PARAMETER_LEN              5
#define OBS_PARAMETER_LEN               3
#define AOBS_PARAMETER_LEN              5
#define COAP_CON_PARAMETER_LEN          3

#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#define BS_EP_PARAMETER_LEN             3
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

#define BS_QUEUE_MODE_PARAMETER_LEN     2
#define RESOURCE_VALUE_PARAMETER_LEN    2
#define FIRMWARE_DOWNLOAD_LEN           2
#define GENERIC_DOWNLOAD_LEN            8

#define SN_NSDL_EP_REGISTER_MESSAGE     1
#define SN_NSDL_EP_UPDATE_MESSAGE       2

#if defined MBED_CONF_MBED_CLIENT_COAP_DISABLE_OBS_FEATURE
#define COAP_DISABLE_OBS_FEATURE MBED_CONF_MBED_CLIENT_COAP_DISABLE_OBS_FEATURE
#endif



/* Constants */
static uint8_t      ep_name_parameter_string[]  = {'e', 'p', '='};      /* Endpoint name. A unique name for the registering node in a domain.  */
static uint8_t      resource_path_ptr[]         = {'r', 'd'};           /* For resource directory */
static uint8_t      resource_type_parameter[]   = {'r', 't', '='};      /* Resource type. Only once for registration */
#ifndef COAP_DISABLE_OBS_FEATURE
static uint8_t      obs_parameter[]             = {'o', 'b', 's'};      /* Observable */
static uint8_t      aobs_parameter[]            = {'a', 'o', 'b', 's', '='}; /* Auto observable */
#endif
static uint8_t      if_description_parameter[]  = {'i', 'f', '='};      /* Interface description. Only once */
static uint8_t      ep_lifetime_parameter[]     = {'l', 't', '='};      /* Lifetime. Number of seconds that this registration will be valid for. Must be updated within this time, or will be removed. */
static uint8_t      version_parameter[]         = {'l', 'w', 'm', '2', 'm', '='}; /* LwM2M Version. Version of the LwM2M Enabler that the LwM2M Client support */
static uint8_t      ep_domain_parameter[]       = {'d', '='};           /* Domain name. If this parameter is missing, a default domain is assumed. */
static uint8_t      coap_con_type_parameter[]   = {'c', 't', '='};      /* CoAP content type */
static uint8_t      resource_value[]            = {'v', '='};           /* Resource value */
#ifdef RESOURCE_ATTRIBUTES_LIST
static uint8_t      name_parameter[]            = {'n', 'a', 'm', 'e', '='};
#endif

static uint8_t      firmware_download_uri[]   = {'f', 'w'}; /* Path for firmware update. */
static uint8_t      generic_download_uri[]    = {'d', 'o', 'w', 'n', 'l', 'o', 'a', 'd'}; /* Path for generic download. */

/* * OMA BS parameters * */
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static uint8_t bs_uri[]                         = {'b', 's'};
static uint8_t bs_ep_name[]                     = {'e', 'p', '='};
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

static uint8_t et_parameter[]                   = {'e', 't', '='};      /* Endpoint type */
static uint8_t bs_queue_mode[]                  = {'b', '='};

/* Function prototypes */
static int32_t          sn_nsdl_internal_coap_send(struct nsdl_s *handle, sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr);
static void             sn_nsdl_resolve_nsp_address(struct nsdl_s *handle);
int8_t                  sn_nsdl_build_registration_body(struct nsdl_s *handle, sn_coap_hdr_s *message_ptr, uint8_t updating_registeration);
static uint16_t         sn_nsdl_calculate_registration_body_size(struct nsdl_s *handle, uint8_t updating_registeration, int8_t *error);
static uint8_t          sn_nsdl_calculate_uri_query_option_len(sn_nsdl_ep_parameters_s *endpoint_info_ptr, uint8_t msg_type, const char *uri_query);
static int8_t           sn_nsdl_fill_uri_query_options(struct nsdl_s *handle, sn_nsdl_ep_parameters_s *parameter_ptr, sn_coap_hdr_s *source_msg_ptr, uint8_t msg_type, const char *uri_query);
static int8_t           sn_nsdl_local_rx_function(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr);
static int8_t           sn_nsdl_resolve_ep_information(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr);
static uint8_t          sn_nsdl_itoa_len(uint32_t value);
static uint8_t          *sn_nsdl_itoa(uint8_t *ptr, uint32_t value);
static int8_t           set_endpoint_info(struct nsdl_s *handle, sn_nsdl_ep_parameters_s *endpoint_info_ptr);
static bool             validateParameters(sn_nsdl_ep_parameters_s *parameter_ptr);
static bool             validate(uint8_t *ptr, uint32_t len, char illegalChar);
static bool             sn_nsdl_check_uint_overflow(uint16_t resource_size, uint16_t param_a, uint16_t param_b);
static void             remove_previous_block_data(struct nsdl_s *handle, sn_nsdl_addr_s *src_ptr, const uint32_t block_number);
static bool             update_last_block_data(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, bool block1);
#if MBED_CONF_MBED_TRACE_ENABLE
static const char      *sn_nsdl_coap_status_description(sn_coap_status_e status);
static const char      *sn_nsdl_coap_message_code_desc(int msg_code);
static const char      *sn_nsdl_coap_message_type_desc(int msg_type);
#endif

static void             sn_nsdl_add_token(struct nsdl_s *handle, uint32_t *token, sn_coap_hdr_s *message_ptr);

int8_t sn_nsdl_destroy(struct nsdl_s *handle)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    if (handle->ep_information_ptr) {
        handle->sn_nsdl_free(handle->ep_information_ptr->endpoint_name_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr->domain_name_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr->location_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr->type_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr->lifetime_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr->version_ptr);
        handle->sn_nsdl_free(handle->ep_information_ptr);
    }

    if (handle->server_address.addr_ptr) {
        handle->sn_nsdl_free(handle->server_address.addr_ptr);
        handle->server_address.addr_ptr = NULL;
        handle->server_address.type = SN_NSDL_ADDRESS_TYPE_NONE;
    }

    /* Destroy also libCoap and grs part of libNsdl */
    sn_coap_protocol_destroy(handle->grs->coap);
    sn_grs_destroy(handle->grs);
    handle->sn_nsdl_free(handle);

    return SN_NSDL_SUCCESS;
}

struct nsdl_s *sn_nsdl_init(uint8_t (*sn_nsdl_tx_cb)(struct nsdl_s *, sn_nsdl_capab_e, uint8_t *, uint16_t, sn_nsdl_addr_s *),
                            uint8_t (*sn_nsdl_rx_cb)(struct nsdl_s *, sn_coap_hdr_s *, sn_nsdl_addr_s *),
                            void *(*sn_nsdl_alloc)(uint16_t), void (*sn_nsdl_free)(void *),
                            uint8_t (*sn_nsdl_auto_obs_token_cb)(struct nsdl_s *, const char *, uint8_t *))
{
    /* Check pointers and define function pointers */
    if (!sn_nsdl_alloc || !sn_nsdl_free || !sn_nsdl_tx_cb || !sn_nsdl_rx_cb) {
        return NULL;
    }

    struct nsdl_s *handle = NULL;

    handle = sn_nsdl_alloc(sizeof(struct nsdl_s));

    if (handle == NULL) {
        return NULL;
    }

    memset(handle, 0, sizeof(struct nsdl_s));

    /* Define function pointers */
    handle->sn_nsdl_alloc = sn_nsdl_alloc;
    handle->sn_nsdl_free = sn_nsdl_free;

    handle->sn_nsdl_tx_callback = sn_nsdl_tx_cb;
    handle->sn_nsdl_rx_callback = sn_nsdl_rx_cb;
    handle->sn_nsdl_auto_obs_token_callback = sn_nsdl_auto_obs_token_cb;

    /* Initialize ep parameters struct */
    if (!handle->ep_information_ptr) {
        handle->ep_information_ptr = handle->sn_nsdl_alloc(sizeof(sn_nsdl_ep_parameters_s));
        if (!handle->ep_information_ptr) {
            sn_nsdl_free(handle);
            return NULL;
        }
        memset(handle->ep_information_ptr, 0, sizeof(sn_nsdl_ep_parameters_s));
    }

    handle->grs = sn_grs_init(sn_nsdl_tx_cb, &sn_nsdl_local_rx_function, sn_nsdl_alloc, sn_nsdl_free);

    /* Initialize GRS */
    if (handle->grs == NULL) {
        handle->sn_nsdl_free(handle->ep_information_ptr);
        handle->ep_information_ptr = 0;
        sn_nsdl_free(handle);
        return NULL;
    }

    sn_nsdl_resolve_nsp_address(handle);

    handle->sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;
    handle->context = NULL;

    randLIB_get_n_bytes_random(&handle->token_seed, sizeof(handle->token_seed));
    if (handle->token_seed == 0) {
        handle->token_seed++;
    }
    return handle;
}

int32_t sn_nsdl_register_endpoint(struct nsdl_s *handle,
                                  sn_nsdl_ep_parameters_s *endpoint_info_ptr,
                                  const char *uri_query_parameters)
{
    /* Local variables */
    sn_coap_hdr_s   *register_message_ptr;
    int32_t        message_id;

    if (endpoint_info_ptr == NULL || handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    // Clear any leftovers from previous registration or bootstrap
    sn_nsdl_clear_coap_sent_blockwise_messages(handle);
    sn_nsdl_clear_coap_received_blockwise_messages(handle);
    sn_nsdl_clear_coap_resending_queue(handle);

    /*** Build endpoint register message ***/
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    handle->is_bs_server = false;
#endif

    /* Allocate memory for header struct */
    register_message_ptr = sn_coap_parser_alloc_message(handle->grs->coap);
    if (register_message_ptr == NULL) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Fill message fields -> confirmable post to specified NSP path */
    register_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    register_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;

    /* Register message content format must be Core Link Format as stated in OMA LwM2M  */
    register_message_ptr->content_format = COAP_CT_LINK_FORMAT;

    /* Allocate memory for the extended options list */
    if (sn_coap_parser_alloc_options(handle->grs->coap, register_message_ptr) == NULL) {
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
        register_message_ptr = 0;
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    register_message_ptr->uri_path_len = sizeof(resource_path_ptr);
    register_message_ptr->uri_path_ptr = resource_path_ptr;

    /* Fill Uri-query options */
    if (SN_NSDL_FAILURE == sn_nsdl_fill_uri_query_options(handle, endpoint_info_ptr,
                                                          register_message_ptr, SN_NSDL_EP_REGISTER_MESSAGE,
                                                          uri_query_parameters)) {
        register_message_ptr->uri_path_ptr = NULL;
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
        return SN_NSDL_FAILURE;
    }

    if (endpoint_info_ptr->ds_register_mode == REGISTER_WITH_RESOURCES) {
        /* Built body for message */
        int ret = sn_nsdl_build_registration_body(handle, register_message_ptr, 0);
        if (ret != SN_NSDL_SUCCESS) {
            register_message_ptr->uri_path_ptr = NULL;
            register_message_ptr->options_list_ptr->uri_host_ptr = NULL;
            sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
            return ret;
        }
    }

#if MBED_CONF_MBED_TRACE_ENABLE
    int i = 0;
    int row_len = 60;
    int max_length = 2048;
    while (i < register_message_ptr->payload_len && i < max_length) {
        if (i + row_len > register_message_ptr->payload_len) {
            row_len = register_message_ptr->payload_len - i;
        }
        tr_info("REGISTER MESSAGE: %.*s", row_len, register_message_ptr->payload_ptr + i);
        i += row_len;
    }
    if (i >= max_length) {
        tr_info("REGISTER MESSAGE:.....");
    }
#endif
    /* Clean (possible) existing and save new endpoint info to handle */
    if (set_endpoint_info(handle, endpoint_info_ptr) == SN_NSDL_FAILURE) {

        handle->sn_nsdl_free(register_message_ptr->payload_ptr);
        register_message_ptr->payload_ptr = NULL;

        register_message_ptr->uri_path_ptr = NULL;
        register_message_ptr->options_list_ptr->uri_host_ptr = NULL;

        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);

        return SN_NSDL_FAILURE;
    }

    sn_nsdl_add_token(handle, &handle->register_token, register_message_ptr);

    /* Build and send coap message to NSP */
    message_id = sn_nsdl_internal_coap_send(handle, register_message_ptr, &handle->server_address);

    handle->sn_nsdl_free(register_message_ptr->payload_ptr);
    register_message_ptr->payload_ptr = NULL;

    register_message_ptr->uri_path_ptr = NULL;
    register_message_ptr->options_list_ptr->uri_host_ptr = NULL;

    register_message_ptr->token_ptr = NULL;
    register_message_ptr->token_len = 0;

    sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);

    return message_id;
}

int32_t sn_nsdl_unregister_endpoint(struct nsdl_s *handle)
{
    /* Local variables */
    sn_coap_hdr_s   *unregister_message_ptr;
    uint8_t         *temp_ptr = 0;
    int32_t        message_id = SN_NSDL_FAILURE;

    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    /* Check that EP have been registered */
    if (sn_nsdl_is_ep_registered(handle)) {

        sn_nsdl_clear_coap_sent_blockwise_messages(handle);
        sn_nsdl_clear_coap_received_blockwise_messages(handle);
        sn_nsdl_clear_coap_resending_queue(handle);

        /* Memory allocation for unregister message */
        unregister_message_ptr = sn_coap_parser_alloc_message(handle->grs->coap);
        if (!unregister_message_ptr) {
            return SN_NSDL_MEMORY_ALLOCATION_FAILED;
        }

        /* Fill unregister message */
        unregister_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
        unregister_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_DELETE;

        if (handle->ep_information_ptr->location_ptr) {
            unregister_message_ptr->uri_path_len = handle->ep_information_ptr->location_len;
            unregister_message_ptr->uri_path_ptr = handle->sn_nsdl_alloc(unregister_message_ptr->uri_path_len);
            if (!unregister_message_ptr->uri_path_ptr) {
                sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, unregister_message_ptr);
                return SN_NSDL_MEMORY_ALLOCATION_FAILED;
            }

            temp_ptr = unregister_message_ptr->uri_path_ptr;

            memcpy(temp_ptr, handle->ep_information_ptr->location_ptr, handle->ep_information_ptr->location_len);
        } else {
            unregister_message_ptr->uri_path_len = (RESOURCE_DIR_LEN + 1 + handle->ep_information_ptr->domain_name_len + 1 + handle->ep_information_ptr->endpoint_name_len);
            unregister_message_ptr->uri_path_ptr = handle->sn_nsdl_alloc(unregister_message_ptr->uri_path_len);
            if (!unregister_message_ptr->uri_path_ptr) {
                sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, unregister_message_ptr);
                return SN_NSDL_MEMORY_ALLOCATION_FAILED;
            }

            temp_ptr = unregister_message_ptr->uri_path_ptr;

            memcpy(temp_ptr, resource_path_ptr, RESOURCE_DIR_LEN);
            temp_ptr += RESOURCE_DIR_LEN;

            *temp_ptr++ = '/';

            memcpy(temp_ptr, handle->ep_information_ptr->domain_name_ptr, handle->ep_information_ptr->domain_name_len);
            temp_ptr += handle->ep_information_ptr->domain_name_len;

            *temp_ptr++ = '/';

            memcpy(temp_ptr, handle->ep_information_ptr->endpoint_name_ptr, handle->ep_information_ptr->endpoint_name_len);
        }

        sn_nsdl_add_token(handle, &handle->unregister_token, unregister_message_ptr);

        /* Send message */
        message_id = sn_nsdl_internal_coap_send(handle, unregister_message_ptr, &handle->server_address);

        unregister_message_ptr->token_ptr = NULL;
        unregister_message_ptr->token_len = 0;

        /* Free memory */
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, unregister_message_ptr);

    }

    return message_id;
}

int32_t sn_nsdl_update_registration(struct nsdl_s *handle, uint8_t *lt_ptr, uint8_t lt_len)
{
    /* Local variables */
    sn_coap_hdr_s   *register_message_ptr;
    uint8_t         *temp_ptr;
    sn_nsdl_ep_parameters_s temp_parameters;
    int32_t        message_id;

    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    if (!sn_nsdl_is_ep_registered(handle)) {
        tr_err("Register update called without registration.");
        return SN_NSDL_FAILURE;
    }

    memset(&temp_parameters, 0, sizeof(sn_nsdl_ep_parameters_s));

    temp_parameters.lifetime_len = lt_len;
    temp_parameters.lifetime_ptr = lt_ptr;

    if (handle->ep_information_ptr) {
        temp_parameters.type_len = handle->ep_information_ptr->type_len;
        temp_parameters.type_ptr = handle->ep_information_ptr->type_ptr;
    }

    /*** Build endpoint register update message ***/

    /* Allocate memory for header struct */
    register_message_ptr = sn_coap_parser_alloc_message(handle->grs->coap);
    if (register_message_ptr == NULL) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Fill message fields -> confirmable post to specified NSP path */
    register_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    register_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;

    /* Register update message content format must be same as register messages content format which is Core Link Format  */
    register_message_ptr->content_format = COAP_CT_LINK_FORMAT;

    if (handle->ep_information_ptr->location_ptr) {
        register_message_ptr->uri_path_len  =   handle->ep_information_ptr->location_len;    /* = Only location set by Device Server*/

        register_message_ptr->uri_path_ptr  =   handle->sn_nsdl_alloc(register_message_ptr->uri_path_len);
        if (!register_message_ptr->uri_path_ptr) {
            sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
            return SN_NSDL_MEMORY_ALLOCATION_FAILED;
        }

        temp_ptr = register_message_ptr->uri_path_ptr;

        /* location */
        memcpy(temp_ptr, handle->ep_information_ptr->location_ptr, handle->ep_information_ptr->location_len);
    } else {
        register_message_ptr->uri_path_len  =   sizeof(resource_path_ptr) + handle->ep_information_ptr->domain_name_len + handle->ep_information_ptr->endpoint_name_len + 2;    /* = rd/domain/endpoint */

        register_message_ptr->uri_path_ptr  =   handle->sn_nsdl_alloc(register_message_ptr->uri_path_len);
        if (!register_message_ptr->uri_path_ptr) {
            sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
            return SN_NSDL_MEMORY_ALLOCATION_FAILED;
        }

        temp_ptr = register_message_ptr->uri_path_ptr;

        /* rd/ */
        memcpy(temp_ptr, resource_path_ptr, sizeof(resource_path_ptr));
        temp_ptr += sizeof(resource_path_ptr);
        *temp_ptr++ = '/';

        /* rd/DOMAIN/ */
        memcpy(temp_ptr, handle->ep_information_ptr->domain_name_ptr, handle->ep_information_ptr->domain_name_len);
        temp_ptr += handle->ep_information_ptr->domain_name_len;
        *temp_ptr++ = '/';

        /* rd/domain/ENDPOINT */
        memcpy(temp_ptr, handle->ep_information_ptr->endpoint_name_ptr, handle->ep_information_ptr->endpoint_name_len);
    }

    /* Allocate memory for the extended options list */
    if (sn_coap_parser_alloc_options(handle->grs->coap, register_message_ptr) == NULL) {
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Fill Uri-query options */
    sn_nsdl_fill_uri_query_options(handle, &temp_parameters, register_message_ptr, SN_NSDL_EP_UPDATE_MESSAGE, NULL);

    /* Build payload */
    if (handle->ep_information_ptr->ds_register_mode == REGISTER_WITH_RESOURCES) {
        int8_t ret = sn_nsdl_build_registration_body(handle, register_message_ptr, 1);
        if (ret != SN_NSDL_SUCCESS) {
            sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);
            return ret;
        }
    }

    sn_nsdl_add_token(handle, &handle->update_register_token, register_message_ptr);

    tr_info("UPDATE REGISTER MESSAGE %.*s", register_message_ptr->payload_len, register_message_ptr->payload_ptr);

    /* Build and send coap message to NSP */
    message_id = sn_nsdl_internal_coap_send(handle, register_message_ptr, &handle->server_address);

    register_message_ptr->token_ptr = NULL;
    register_message_ptr->token_len = 0;

    handle->sn_nsdl_free(register_message_ptr->payload_ptr);

    sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, register_message_ptr);

    return message_id;
}

int8_t sn_nsdl_set_endpoint_location(struct nsdl_s *handle, uint8_t *location_ptr, uint8_t location_len)
{
    if (!handle || !location_ptr || (location_len == 0)) {
        return SN_NSDL_FAILURE;
    }

    handle->sn_nsdl_free(handle->ep_information_ptr->location_ptr);
    handle->ep_information_ptr->location_ptr = handle->sn_nsdl_alloc(location_len);
    memcpy(handle->ep_information_ptr->location_ptr, location_ptr, location_len);
    handle->ep_information_ptr->location_len = location_len;

    return SN_NSDL_SUCCESS;
}

void sn_nsdl_nsp_lost(struct nsdl_s *handle)
{
    /* Check parameters */
    if (handle == NULL) {
        return;
    }

    handle->sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_NOT_REGISTERED;
}

int8_t sn_nsdl_is_ep_registered(struct nsdl_s *handle)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    return handle->sn_nsdl_endpoint_registered;
}

int32_t sn_nsdl_send_observation_notification(struct nsdl_s *handle, uint8_t *token_ptr, uint8_t token_len,
                                              uint8_t *payload_ptr, uint16_t payload_len, sn_coap_observe_e observe, bool confirmable,
                                              sn_coap_content_format_e content_format,
                                              const int32_t message_id, const uint32_t max_age)
{
    sn_coap_hdr_s   *notification_message_ptr;
    int32_t         return_msg_id = 0;

    /* Check parameters */
    if (handle == NULL || handle->grs == NULL || token_len == 0) {
        return SN_NSDL_FAILURE;
    }

    /* Allocate and initialize memory for header struct */
    notification_message_ptr = sn_coap_parser_alloc_message(handle->grs->coap);
    if (notification_message_ptr == NULL) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    if (sn_coap_parser_alloc_options(handle->grs->coap, notification_message_ptr) == NULL) {
        handle->sn_nsdl_free(notification_message_ptr);
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    sn_coap_msg_type_e type = COAP_MSG_TYPE_CONFIRMABLE;
    if (!confirmable) {
        type = COAP_MSG_TYPE_NON_CONFIRMABLE;
    }

    /* Fill header */
    notification_message_ptr->msg_type = type;
    notification_message_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;

    /* Fill token */
    notification_message_ptr->token_len = token_len;
    notification_message_ptr->token_ptr = token_ptr;

    /* Fill payload */
    notification_message_ptr->payload_len = payload_len;
    notification_message_ptr->payload_ptr = payload_ptr;

    /* Fill observe */
    notification_message_ptr->options_list_ptr->observe = observe;
    notification_message_ptr->options_list_ptr->max_age = max_age;

    /* Fill content format */
    notification_message_ptr->content_format = content_format;

    if (message_id != -1) {
        notification_message_ptr->msg_id = message_id;
    }

    /* Send message */
    return_msg_id = sn_nsdl_send_coap_message(handle, &handle->server_address, notification_message_ptr);
    if (return_msg_id >= SN_NSDL_SUCCESS) {
        return_msg_id = notification_message_ptr->msg_id;
    }

    /* Free memory */
    notification_message_ptr->payload_ptr = NULL;
    notification_message_ptr->token_ptr = NULL;

    sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, notification_message_ptr);

    return return_msg_id;
}

/* * * * * * * * * * */
/* ~ OMA functions ~ */
/* * * * * * * * * * */

int32_t sn_nsdl_oma_bootstrap(struct nsdl_s *handle,
                              sn_nsdl_addr_s *bootstrap_address_ptr,
                              sn_nsdl_ep_parameters_s *endpoint_info_ptr,
                              const char *uri_query_parameters)
{
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /* Local variables */
    sn_coap_hdr_s bootstrap_coap_header;
    uint8_t *uri_query_tmp_ptr;
    int32_t message_id;

    /* Check parameters */
    if (!bootstrap_address_ptr || !endpoint_info_ptr || !handle) {
        return SN_NSDL_FAILURE;
    }

    int8_t ret = set_NSP_address(handle,
                                 bootstrap_address_ptr->addr_ptr,
                                 bootstrap_address_ptr->addr_len,
                                 bootstrap_address_ptr->port,
                                 bootstrap_address_ptr->type);
    if (ret != SN_NSDL_SUCCESS) {
        return ret;
    }

    handle->is_bs_server = true;

    /* XXX FIX -- Init CoAP header struct */
    sn_coap_parser_init_message(&bootstrap_coap_header);

    if (!sn_coap_parser_alloc_options(handle->grs->coap, &bootstrap_coap_header)) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Build bootstrap start message */
    bootstrap_coap_header.msg_code = COAP_MSG_CODE_REQUEST_POST;
    bootstrap_coap_header.msg_type = COAP_MSG_TYPE_CONFIRMABLE;

    bootstrap_coap_header.uri_path_ptr = bs_uri;
    bootstrap_coap_header.uri_path_len = sizeof(bs_uri);

    size_t query_len = endpoint_info_ptr->endpoint_name_len + BS_EP_PARAMETER_LEN;
    size_t optional_params_len = 0;
    if (uri_query_parameters) {
        optional_params_len = strlen(uri_query_parameters);
    }

    query_len += optional_params_len;

    if (query_len > MAX_URI_QUERY_LEN) {
        handle->sn_nsdl_free(bootstrap_coap_header.options_list_ptr);
        tr_error("sn_nsdl_oma_bootstrap - max param length reached (%lu)", (unsigned long)query_len);
        return SN_NSDL_FAILURE;
    }

    uri_query_tmp_ptr = handle->sn_nsdl_alloc(query_len);
    if (!uri_query_tmp_ptr) {
        handle->sn_nsdl_free(bootstrap_coap_header.options_list_ptr);
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    memcpy(uri_query_tmp_ptr, bs_ep_name, BS_EP_PARAMETER_LEN);
    memcpy((uri_query_tmp_ptr + BS_EP_PARAMETER_LEN),
           endpoint_info_ptr->endpoint_name_ptr,
           endpoint_info_ptr->endpoint_name_len);

    if (optional_params_len > 0) {
        memcpy(uri_query_tmp_ptr + endpoint_info_ptr->endpoint_name_len + BS_EP_PARAMETER_LEN,
               uri_query_parameters,
               optional_params_len);
    }

    bootstrap_coap_header.options_list_ptr->uri_query_len = query_len;
    bootstrap_coap_header.options_list_ptr->uri_query_ptr = uri_query_tmp_ptr;

    /* Save bootstrap server address */
    sn_nsdl_add_token(handle, &handle->bootstrap_token, &bootstrap_coap_header);

    /* Send message */
    message_id = sn_nsdl_internal_coap_send(handle, &bootstrap_coap_header, bootstrap_address_ptr);

    /* Free allocated memory */
    handle->sn_nsdl_free(uri_query_tmp_ptr);
    handle->sn_nsdl_free(bootstrap_coap_header.options_list_ptr);

    return message_id;
#else
    return SN_NSDL_FAILURE;
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

}

char *sn_nsdl_get_version(void)
{
#if defined(YOTTA_MBED_CLIENT_C_VERSION_STRING)
    return YOTTA_MBED_CLIENT_C_VERSION_STRING;
#elif defined(VERSION)
    return VERSION;
#else
    return "0.0.0";
#endif
}

int8_t sn_nsdl_process_coap(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *src_ptr)
{
    sn_coap_hdr_s           *coap_response_ptr  = NULL;
    sn_nsdl_dynamic_resource_parameters_s *resource = NULL;

    /* Check parameters */
    if (handle == NULL || coap_packet_ptr == NULL) {
        return SN_NSDL_FAILURE;
    }

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
    if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_DUPLICATED_MSG) {
        tr_info("sn_nsdl_process_coap - received duplicate message, ignore");
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
        return SN_NSDL_SUCCESS;
    }
#endif

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    // Pass block to application if external_memory_block is set
    if (coap_packet_ptr->options_list_ptr &&
            coap_packet_ptr->options_list_ptr->block1 != -1 &&
            (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING ||
             coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED)) {
        char *path = handle->sn_nsdl_alloc(coap_packet_ptr->uri_path_len + 1);
        if (!path) {
            return SN_NSDL_MEMORY_ALLOCATION_FAILED;
        }
        memcpy(path,
               coap_packet_ptr->uri_path_ptr,
               coap_packet_ptr->uri_path_len);
        path[coap_packet_ptr->uri_path_len] = '\0';

        resource = sn_nsdl_get_resource(handle, path);
        handle->sn_nsdl_free(path);
        if (resource && resource->static_resource_parameters->external_memory_block) {
            return sn_grs_process_coap(handle, coap_packet_ptr, src_ptr);
        }
    }
#endif

    // Handling of GET responses
    if (coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT) {
        bool data_updated = false;
        if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->block2 != -1) {
            uint32_t block_number = coap_packet_ptr->options_list_ptr->block2 >> 4;
            if (block_number) {
                remove_previous_block_data(handle, src_ptr, block_number);
            }

            // Modify payload to have only last received block data
            data_updated = update_last_block_data(handle, coap_packet_ptr, false);
        }

        handle->sn_nsdl_rx_callback(handle, coap_packet_ptr, src_ptr);
        if (data_updated) {
            handle->grs->coap->sn_coap_protocol_free(coap_packet_ptr->payload_ptr);
        }

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
        // Remove sent blockwise message(GET request) from the linked list.
        sn_coap_protocol_remove_sent_blockwise_message(handle->grs->coap, coap_packet_ptr->msg_id);
#endif

        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
        return SN_NSDL_SUCCESS;
    }

    /* Check, if coap itself sends response, or block receiving is ongoing... */
    if (coap_packet_ptr->coap_status != COAP_STATUS_OK &&
            coap_packet_ptr->coap_status != COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED &&
            coap_packet_ptr) {
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
        return SN_NSDL_SUCCESS;
    }

    /* If proxy options added, return not supported */
    if (coap_packet_ptr->options_list_ptr) {
        if (coap_packet_ptr->options_list_ptr->proxy_uri_len) {
            coap_response_ptr = sn_coap_build_response(handle->grs->coap, coap_packet_ptr, COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED);
            if (coap_response_ptr) {
                sn_nsdl_send_coap_message(handle, src_ptr, coap_response_ptr);
                sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_response_ptr);
                sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
                return SN_NSDL_SUCCESS;
            } else {
                sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
                return SN_NSDL_FAILURE;
            }
        }
    }

    /* * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* If message is response message, call RX callback  */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * */

    if (((coap_packet_ptr->msg_code > COAP_MSG_CODE_REQUEST_DELETE) ||
            (coap_packet_ptr->msg_type >= COAP_MSG_TYPE_ACKNOWLEDGEMENT))) {
        int8_t retval = sn_nsdl_local_rx_function(handle, coap_packet_ptr, src_ptr);
        if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED &&
                coap_packet_ptr->payload_ptr) {
            handle->sn_nsdl_free(coap_packet_ptr->payload_ptr);
            coap_packet_ptr->payload_ptr = 0;
        }
        sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
        return retval;
    }
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /* * If OMA bootstrap message... * */
    bool bootstrap_msg = handle->is_bs_server;

    // Pass bootstrap data to application
    if (bootstrap_msg) {
        // If retval is 2 skip the freeing, it will be done in MBED_CLIENT_NSDLINTERFACE_BS_PUT_EVENT event
        if (handle->sn_nsdl_rx_callback(handle, coap_packet_ptr, src_ptr) != 2) {
            if (coap_packet_ptr &&
                    coap_packet_ptr->options_list_ptr &&
                    coap_packet_ptr->coap_status != COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED &&
                    coap_packet_ptr->options_list_ptr->block1 != -1) {
                handle->sn_nsdl_free(coap_packet_ptr->payload_ptr);
                coap_packet_ptr->payload_ptr = NULL;
            }
            sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, coap_packet_ptr);
        }

        return SN_NSDL_SUCCESS;
    }
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    /* * * * * * * * * * * * * * * */
    /* Other messages are for GRS  */
    /* * * * * * * * * * * * * * * */
    return sn_grs_process_coap(handle, coap_packet_ptr, src_ptr);
}

int8_t sn_nsdl_exec(struct nsdl_s *handle, uint32_t time)
{
    if (!handle || !handle->grs) {
        return SN_NSDL_FAILURE;
    }
    /* Call CoAP execution function */
    return sn_coap_protocol_exec(handle->grs->coap, time);
}

sn_nsdl_dynamic_resource_parameters_s *sn_nsdl_get_resource(struct nsdl_s *handle, const char *path_ptr)
{
    /* Check parameters */
    if (handle == NULL) {
        return NULL;
    }

    return sn_grs_search_resource(handle->grs, path_ptr, SN_GRS_SEARCH_METHOD);
}


/**
 * \fn static int32_t sn_nsdl_internal_coap_send(struct nsdl_s *handle, sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr)
 *
 *
 * \brief To send NSDL messages. Stores message id?s and message description to catch response from NSP server
 * \param   *handle             Pointer to nsdl-library handle
 * \param   *coap_header_ptr    Pointer to the CoAP message header to be sent
 * \param   *dst_addr_ptr       Pointer to the address structure that contains destination address information
 * \param   message_description Message description to be stored to list for waiting response
 *
 * \return  message id, < 0 if failed
 */
static int32_t sn_nsdl_internal_coap_send(struct nsdl_s *handle, sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr)
{
    uint8_t     *coap_message_ptr   = NULL;
    int32_t     coap_message_len    = 0;

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
    int8_t ret_val = prepare_blockwise_message(handle->grs->coap, coap_header_ptr);
    if (0 != ret_val) {
        return SN_NSDL_FAILURE;
    }
#endif

    coap_message_len = sn_coap_builder_calc_needed_packet_data_size_2(coap_header_ptr, handle->grs->coap->sn_coap_block_data_size);
    tr_debug("sn_nsdl_internal_coap_send - msg len: %" PRId32 "", coap_message_len);
    if (coap_message_len <= 0) {
        return SN_NSDL_FAILURE;
    }

    coap_message_ptr = handle->sn_nsdl_alloc(coap_message_len);
    if (!coap_message_ptr) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Build message */
    int16_t ret = sn_coap_protocol_build(handle->grs->coap, dst_addr_ptr, coap_message_ptr, coap_header_ptr, (void *)handle);
    if (ret < 0) {
        handle->sn_nsdl_free(coap_message_ptr);
        return ret;
    }

    handle->sn_nsdl_tx_callback(handle, SN_NSDL_PROTOCOL_COAP, coap_message_ptr, coap_message_len, dst_addr_ptr);
    handle->sn_nsdl_free(coap_message_ptr);

    return coap_header_ptr->msg_id;
}

/**
 * \fn static void sn_nsdl_resolve_nsp_address(struct nsdl_s *handle)
 *
 * \brief Resolves NSP server address.
 *
 * \param *handle Pointer to nsdl-library handle
 * \note Application must set NSP address with set_nsp_address
 */
static void sn_nsdl_resolve_nsp_address(struct nsdl_s *handle)
{
    memset(&handle->server_address, 0, sizeof(sn_nsdl_addr_s));
    handle->server_address.type = SN_NSDL_ADDRESS_TYPE_NONE;
}

#ifdef RESOURCE_ATTRIBUTES_LIST
static char *sn_nsdl_build_resource_attribute_str(char *dst, const sn_nsdl_attribute_item_s *attribute, const char *name, const size_t name_len)
{
    if (attribute != NULL && name != NULL && name_len > 0 && attribute->value) {
        size_t attribute_len = strlen(attribute->value);
        *dst++ = ';';
        memcpy(dst, name, name_len);
        dst += name_len;
        *dst++ = '"';
        memcpy(dst,
               attribute->value,
               attribute_len);
        dst += attribute_len;
        *dst++ = '"';
    }
    return dst;
}
#endif

/**
 * \fn int8_t sn_nsdl_build_registration_body(struct nsdl_s *handle, sn_coap_hdr_s *message_ptr, uint8_t updating_registeration)
 *
 * \brief   To build GRS resources to registration message payload
 * \param *handle Pointer to nsdl-library handle
 * \param   *message_ptr Pointer to CoAP message header
 *
 * \return  SN_NSDL_SUCCESS = 0, Failed < 0
 */
int8_t sn_nsdl_build_registration_body(struct nsdl_s *handle, sn_coap_hdr_s *message_ptr, uint8_t updating_registeration)
{
    tr_debug("sn_nsdl_build_registration_body");
    /* Local variables */
    uint8_t                 *temp_ptr;
    sn_nsdl_dynamic_resource_parameters_s   *resource_temp_ptr;

    /* Calculate needed memory and allocate */
    int8_t error = 0;
    uint16_t msg_len = sn_nsdl_calculate_registration_body_size(handle, updating_registeration, &error);
    if (SN_NSDL_FAILURE == error) {
        return error;
    }

    if (!msg_len) {
        return SN_NSDL_SUCCESS;
    } else {
        message_ptr->payload_len = msg_len;
    }
    tr_debug("sn_nsdl_build_registration_body - body size: [%d]", message_ptr->payload_len);
    message_ptr->payload_ptr = handle->sn_nsdl_alloc(message_ptr->payload_len);
    if (!message_ptr->payload_ptr) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    /* Build message */
    temp_ptr = message_ptr->payload_ptr;

    resource_temp_ptr = sn_grs_get_first_resource(handle->grs);

    /* Loop trough all resources */
    while (resource_temp_ptr) {
        /* if resource needs to be registered */
        if (resource_temp_ptr->publish_uri) {
            if (!resource_temp_ptr->always_publish && updating_registeration && resource_temp_ptr->registered == SN_NDSL_RESOURCE_REGISTERED) {
                resource_temp_ptr = sn_grs_get_next_resource(handle->grs, resource_temp_ptr);
                continue;
            } else if (resource_temp_ptr->registered != SN_NDSL_RESOURCE_DELETE) {
                resource_temp_ptr->registered = SN_NDSL_RESOURCE_REGISTERED;
            }

            /* If not first resource, add '.' to separator */
            if (temp_ptr != message_ptr->payload_ptr) {
                *temp_ptr++ = ',';
            }

            *temp_ptr++ = '<';
            *temp_ptr++ = '/';
            size_t path_len = 0;
            if (resource_temp_ptr->static_resource_parameters->path) {
                path_len = strlen(resource_temp_ptr->static_resource_parameters->path);
            }
            memcpy(temp_ptr,
                   resource_temp_ptr->static_resource_parameters->path,
                   path_len);
            temp_ptr += path_len;
            *temp_ptr++ = '>';

            /* Resource attributes */
            if (resource_temp_ptr->registered == SN_NDSL_RESOURCE_DELETE) {
                *temp_ptr++ = ';';
                *temp_ptr++ = 'd';
            }
#ifndef RESOURCE_ATTRIBUTES_LIST
#ifndef DISABLE_RESOURCE_TYPE
            size_t resource_type_len = 0;
            if (resource_temp_ptr->static_resource_parameters->resource_type_ptr) {
                resource_type_len = strlen(resource_temp_ptr->static_resource_parameters->resource_type_ptr);
            }
            if (resource_type_len) {
                *temp_ptr++ = ';';
                memcpy(temp_ptr, resource_type_parameter, RT_PARAMETER_LEN);
                temp_ptr += RT_PARAMETER_LEN;
                *temp_ptr++ = '"';
                memcpy(temp_ptr,
                       resource_temp_ptr->static_resource_parameters->resource_type_ptr,
                       resource_type_len);
                temp_ptr += resource_type_len;
                *temp_ptr++ = '"';
            }
#endif
#ifndef DISABLE_INTERFACE_DESCRIPTION
            size_t interface_description_len = 0;
            if (resource_temp_ptr->static_resource_parameters->interface_description_ptr) {
                interface_description_len = strlen(resource_temp_ptr->static_resource_parameters->interface_description_ptr);
            }

            if (interface_description_len) {
                *temp_ptr++ = ';';
                memcpy(temp_ptr, if_description_parameter, IF_PARAMETER_LEN);
                temp_ptr += IF_PARAMETER_LEN;
                *temp_ptr++ = '"';
                memcpy(temp_ptr,
                       resource_temp_ptr->static_resource_parameters->interface_description_ptr,
                       interface_description_len);
                temp_ptr += interface_description_len;
                *temp_ptr++ = '"';
            }
#endif
#else
            size_t attribute_len = 0;
            if (resource_temp_ptr->static_resource_parameters->attributes_ptr) {
                sn_nsdl_attribute_item_s *attribute = resource_temp_ptr->static_resource_parameters->attributes_ptr;
                while (attribute->attribute_name != ATTR_END) {
                    switch (attribute->attribute_name) {
                        case ATTR_RESOURCE_TYPE:
                            temp_ptr = sn_nsdl_build_resource_attribute_str(temp_ptr, attribute, resource_type_parameter, RT_PARAMETER_LEN);
                            break;
                        case ATTR_INTERFACE_DESCRIPTION:
                            temp_ptr = sn_nsdl_build_resource_attribute_str(temp_ptr, attribute, if_description_parameter, IF_PARAMETER_LEN);
                            break;
                        case ATTR_ENDPOINT_NAME:
                            temp_ptr = sn_nsdl_build_resource_attribute_str(temp_ptr, attribute, name_parameter, NAME_PARAMETER_LEN);
                            break;
                        default:
                            break;
                    }
                    attribute++;
                }
            }
#endif
            if (resource_temp_ptr->coap_content_type != 0) {
                *temp_ptr++ = ';';
                memcpy(temp_ptr, coap_con_type_parameter, COAP_CON_PARAMETER_LEN);
                temp_ptr += COAP_CON_PARAMETER_LEN;
                *temp_ptr++ = '"';
                temp_ptr = sn_nsdl_itoa(temp_ptr,
                                        resource_temp_ptr->coap_content_type);
                *temp_ptr++ = '"';
            }

            /* ;v */
            if ((resource_temp_ptr->publish_value > 0) && resource_temp_ptr->resource) {
                // If the resource is Opaque then do Base64 encoding of data
                if (resource_temp_ptr->publish_value == 2) {
                    size_t dst_size = (((resource_temp_ptr->resource_len + 2) / 3) << 2) + 1;
                    unsigned char *dst = (unsigned char *)handle->sn_nsdl_alloc(dst_size);
                    size_t olen = 0;
                    if (dst) {
                        if (mbedtls_base64_encode(dst, dst_size, &olen,
                                                  resource_temp_ptr->resource, resource_temp_ptr->resource_len) == 0) {
                            *temp_ptr++ = ';';
                            memcpy(temp_ptr, resource_value, RESOURCE_VALUE_PARAMETER_LEN);
                            temp_ptr += RESOURCE_VALUE_PARAMETER_LEN;
                            *temp_ptr++ = '"';
                            memcpy(temp_ptr, dst, olen);
                            temp_ptr += olen;
                            *temp_ptr++ = '"';

                        }
                        handle->sn_nsdl_free(dst);
                    }

                } else {      // For resources which does not require Base64 encoding of data
                    *temp_ptr++ = ';';
                    memcpy(temp_ptr, resource_value, RESOURCE_VALUE_PARAMETER_LEN);
                    temp_ptr += RESOURCE_VALUE_PARAMETER_LEN;
                    *temp_ptr++ = '"';
                    memcpy(temp_ptr, resource_temp_ptr->resource, resource_temp_ptr->resource_len);
                    temp_ptr += resource_temp_ptr->resource_len;
                    *temp_ptr++ = '"';
                }
            }

            /* ;aobs / ;obs */
            // This needs to be re-visited and may be need an API for maganging obs value for different server implementation
#ifndef COAP_DISABLE_OBS_FEATURE
            if (resource_temp_ptr->auto_observable) {
                uint8_t token[MAX_TOKEN_SIZE] = {0};
                uint8_t len = handle->sn_nsdl_auto_obs_token_callback(handle,
                                                                      resource_temp_ptr->static_resource_parameters->path,
                                                                      (uint8_t *)token);
                if (len > 0) {
                    *temp_ptr++ = ';';
                    memcpy(temp_ptr, aobs_parameter, AOBS_PARAMETER_LEN);
                    temp_ptr += AOBS_PARAMETER_LEN;
                    *temp_ptr++ = '"';
                    uint16_t temp = common_read_16_bit((uint8_t *)token);
                    temp_ptr = sn_nsdl_itoa(temp_ptr, temp);
                    *temp_ptr++ = '"';
                }
            } else if (resource_temp_ptr->observable) {
                *temp_ptr++ = ';';
                memcpy(temp_ptr, obs_parameter, OBS_PARAMETER_LEN);
                temp_ptr += OBS_PARAMETER_LEN;
            }
#endif
        }
        resource_temp_ptr = sn_grs_get_next_resource(handle->grs, resource_temp_ptr);

    }
    return SN_NSDL_SUCCESS;
}

/**
 * \fn static uint16_t sn_nsdl_calculate_registration_body_size(struct nsdl_s *handle, uint8_t updating_registeration, int8_t *error)
 *
 *
 * \brief   Calculates registration message payload size
 * \param   *handle                 Pointer to nsdl-library handle
 * \param   *updating_registeration Pointer to list of GRS resources
 * \param   *error                  Error code, SN_NSDL_SUCCESS or SN_NSDL_FAILURE
 *
 * \return  Needed payload size
 */
static uint16_t sn_nsdl_calculate_registration_body_size(struct nsdl_s *handle, uint8_t updating_registeration, int8_t *error)
{
    tr_debug("sn_nsdl_calculate_registration_body_size");
    /* Local variables */
    uint16_t return_value = 0;
    *error = SN_NSDL_SUCCESS;
    const sn_nsdl_dynamic_resource_parameters_s *resource_temp_ptr;

    /* check pointer */
    resource_temp_ptr = sn_grs_get_first_resource(handle->grs);

    while (resource_temp_ptr) {
        if (resource_temp_ptr->publish_uri) {
            if (!resource_temp_ptr->always_publish && updating_registeration && resource_temp_ptr->registered == SN_NDSL_RESOURCE_REGISTERED) {
                resource_temp_ptr = sn_grs_get_next_resource(handle->grs, resource_temp_ptr);
                continue;
            }
            /* If not first resource, then '.' will be added */
            if (return_value) {
                if (sn_nsdl_check_uint_overflow(return_value, 1, 0)) {
                    return_value++;
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }

            /* Count length for the resource path </path> */
            size_t path_len = 0;
            if (resource_temp_ptr->static_resource_parameters->path) {
                path_len = strlen(resource_temp_ptr->static_resource_parameters->path);
            }

            if (sn_nsdl_check_uint_overflow(return_value, 3, path_len)) {
                return_value += (3 + path_len);
            } else {
                *error = SN_NSDL_FAILURE;
                break;
            }

            /* Count lengths of the attributes */
            if (resource_temp_ptr->registered == SN_NDSL_RESOURCE_DELETE) {
                return_value += 2;
            }
#ifndef RESOURCE_ATTRIBUTES_LIST
#ifndef DISABLE_RESOURCE_TYPE
            /* Resource type parameter */
            size_t resource_type_len = 0;
            if (resource_temp_ptr->static_resource_parameters->resource_type_ptr) {
                resource_type_len = strlen(resource_temp_ptr->static_resource_parameters->resource_type_ptr);
            }

            if (resource_type_len) {
                /* ;rt="restype" */
                if (sn_nsdl_check_uint_overflow(return_value,
                                                6,
                                                resource_type_len)) {
                    return_value += (6 + resource_type_len);
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }
#endif

#ifndef DISABLE_INTERFACE_DESCRIPTION
            /* Interface description parameter */
            size_t interface_description_len = 0;
            if (resource_temp_ptr->static_resource_parameters->interface_description_ptr) {
                interface_description_len = strlen(resource_temp_ptr->static_resource_parameters->interface_description_ptr);
            }
            if (interface_description_len) {
                /* ;if="iftype" */
                if (sn_nsdl_check_uint_overflow(return_value,
                                                6,
                                                interface_description_len)) {
                    return_value += (6 + interface_description_len);
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }
#endif
#else
            /* All attributes */
            if (resource_temp_ptr->static_resource_parameters->attributes_ptr) {
                size_t attribute_len = 0;
                size_t attribute_desc_len = 0;
                uint8_t success = 1;
                sn_nsdl_attribute_item_s *item = resource_temp_ptr->static_resource_parameters->attributes_ptr;
                while (item->attribute_name != ATTR_END) {
                    switch (item->attribute_name) {
                        case ATTR_RESOURCE_TYPE:
                            /* ;rt="restype" */
                            attribute_desc_len = 6;
                            attribute_len = strlen(item->value);
                            break;
                        case ATTR_INTERFACE_DESCRIPTION:
                            /* ;if="iftype" */
                            attribute_desc_len = 6;
                            attribute_len = strlen(item->value);
                            break;
                        case ATTR_ENDPOINT_NAME:
                            /* ;name="name" */
                            attribute_desc_len = 8;
                            attribute_len = strlen(item->value);
                            break;
                        default:
                            break;
                    }
                    if (sn_nsdl_check_uint_overflow(return_value,
                                                    attribute_desc_len,
                                                    attribute_len)) {
                        return_value += (attribute_desc_len + attribute_len);
                    } else {
                        success = 0;
                        break;
                    }
                    item++;
                }
                if (!success) {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }
#endif
            if (resource_temp_ptr->coap_content_type != 0) {
                /* ;if="content" */
                uint8_t len = sn_nsdl_itoa_len(resource_temp_ptr->coap_content_type);
                if (sn_nsdl_check_uint_overflow(return_value, 6, len)) {
                    return_value += (6 + len);
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }

            if ((resource_temp_ptr->publish_value > 0) && resource_temp_ptr->resource) {
                /* ;v="" */
                uint16_t len = resource_temp_ptr->resource_len;
                if (resource_temp_ptr->publish_value == 2) {
                    len = (((resource_temp_ptr->resource_len + 2) / 3) << 2);
                }
                if (sn_nsdl_check_uint_overflow(return_value, 5, len)) {
                    return_value += 5 + len;
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
                /* ;v="" */
            }

#ifndef COAP_DISABLE_OBS_FEATURE
            // Auto obs will take higher priority
            // This needs to be re-visited and may be need an API for maganging obs value for different server implementation
            if (resource_temp_ptr->auto_observable) {
                /* ;aobs="" */
                uint8_t token[MAX_TOKEN_SIZE] = {0};
                uint8_t len = handle->sn_nsdl_auto_obs_token_callback(handle,
                                                                      resource_temp_ptr->static_resource_parameters->path,
                                                                      (uint8_t *)token);

                if (len > 0) {
                    uint16_t temp = common_read_16_bit((uint8_t *)token);
                    uint8_t token_len = sn_nsdl_itoa_len(temp);
                    if (sn_nsdl_check_uint_overflow(return_value, 8, token_len)) {
                        return_value += (8 + token_len);
                    } else {
                        *error = SN_NSDL_FAILURE;
                        break;
                    }
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            } else if (resource_temp_ptr->observable) {
                if (sn_nsdl_check_uint_overflow(return_value, 4, 0)) {
                    return_value += 4;
                } else {
                    *error = SN_NSDL_FAILURE;
                    break;
                }
            }
#endif
        }
        resource_temp_ptr = sn_grs_get_next_resource(handle->grs, resource_temp_ptr);
    }
    return return_value;
}

/**
 * \fn static uint8_t sn_nsdl_calculate_uri_query_option_len(sn_nsdl_ep_parameters_s *endpoint_info_ptr, uint8_t msg_type)
 *
 *
 * \brief Calculates needed uri query option length
 *
 * \param *endpoint_info_ptr    Pointer to endpoint info structure
 * \param msg_type              Message type
 *
 * \return  number of parameters in uri query
 */
static uint8_t sn_nsdl_calculate_uri_query_option_len(sn_nsdl_ep_parameters_s *endpoint_info_ptr,
                                                      uint8_t msg_type,
                                                      const char *uri_query)
{
    uint16_t return_value = 0;
    uint8_t number_of_parameters = 0;


    if ((endpoint_info_ptr->endpoint_name_len != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE) && endpoint_info_ptr->endpoint_name_ptr != 0) {
        return_value += endpoint_info_ptr->endpoint_name_len;
        return_value += EP_NAME_PARAMETERS_LEN; //ep=
        number_of_parameters++;
    }

    if ((endpoint_info_ptr->type_len != 0) &&
            (msg_type == SN_NSDL_EP_REGISTER_MESSAGE || msg_type == SN_NSDL_EP_UPDATE_MESSAGE) &&
            (endpoint_info_ptr->type_ptr != 0)) {
        return_value += endpoint_info_ptr->type_len;
        return_value += ET_PARAMETER_LEN;       //et=
        number_of_parameters++;
    }

    if ((endpoint_info_ptr->lifetime_len != 0) && (endpoint_info_ptr->lifetime_ptr != 0)) {
        return_value += endpoint_info_ptr->lifetime_len;
        return_value += LT_PARAMETER_LEN;       //lt=
        number_of_parameters++;
    }

    if ((endpoint_info_ptr->version_len != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE) &&
            endpoint_info_ptr->version_ptr != 0) {
        return_value += endpoint_info_ptr->version_len;
        return_value += VERSION_PARAMETER_LEN;   //lwm2m=
        number_of_parameters++;
    }

    if ((endpoint_info_ptr->domain_name_len != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE) && (endpoint_info_ptr->domain_name_ptr != 0)) {
        return_value += endpoint_info_ptr->domain_name_len;
        return_value += DOMAIN_PARAMETER_LEN;       //d=
        number_of_parameters++;
    }

    if (((endpoint_info_ptr->binding_and_mode & 0x04) || (endpoint_info_ptr->binding_and_mode & 0x01)) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE)) {
        return_value += BS_QUEUE_MODE_PARAMETER_LEN;

        if (endpoint_info_ptr->binding_and_mode & 0x01) {
            return_value++;
        }
        if (endpoint_info_ptr->binding_and_mode & 0x04) {
            return_value++;
        }
        if ((endpoint_info_ptr->binding_and_mode & 0x02) && ((endpoint_info_ptr->binding_and_mode & 0x04) || (endpoint_info_ptr->binding_and_mode & 0x01))) {
            return_value++;
        }

        number_of_parameters++;
    }

    if (number_of_parameters != 0) {
        return_value += (number_of_parameters - 1);
    }

    if (uri_query) {
        return_value += strlen(uri_query);
    }

    if (return_value > MAX_URI_QUERY_LEN) {
        tr_error("sn_nsdl_calculate_uri_query_option_len - max param length reached (%d)", return_value);
        return_value = 0;
    }

    return return_value;
}

/**
 * \fn static int8_t sn_nsdl_fill_uri_query_options(struct nsdl_s *handle, sn_nsdl_ep_parameters_s *parameter_ptr, sn_coap_hdr_s *source_msg_ptr, uint8_t msg_type)
 *
 *
 * \brief Fills uri-query options to message header struct
 * \param *handle           Pointer to nsdl-library handle
 * \param *parameter_ptr    Pointer to endpoint parameters struct
 * \param *source_msg_ptr   Pointer to CoAP header struct
 * \param msg_type          Message type
 *
 * \return  SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_fill_uri_query_options(struct nsdl_s *handle,
                                             sn_nsdl_ep_parameters_s *parameter_ptr,
                                             sn_coap_hdr_s *source_msg_ptr,
                                             uint8_t msg_type,
                                             const char *uri_query)
{
    uint8_t *temp_ptr = NULL;
    if (!validateParameters(parameter_ptr)) {
        return SN_NSDL_FAILURE;
    }

    size_t query_len = sn_nsdl_calculate_uri_query_option_len(parameter_ptr, msg_type, uri_query);
    if (query_len == 0) {
        return 0;
    }

    source_msg_ptr->options_list_ptr->uri_query_len = query_len;
    source_msg_ptr->options_list_ptr->uri_query_ptr = handle->sn_nsdl_alloc(query_len);

    if (source_msg_ptr->options_list_ptr->uri_query_ptr == NULL) {
        return SN_NSDL_FAILURE;
    }
    memset(source_msg_ptr->options_list_ptr->uri_query_ptr, 0, source_msg_ptr->options_list_ptr->uri_query_len);

    temp_ptr = source_msg_ptr->options_list_ptr->uri_query_ptr;

    /******************************************************/
    /* If endpoint name is configured, fill needed fields */
    /******************************************************/

    if ((parameter_ptr->endpoint_name_len != 0) &&
            (parameter_ptr->endpoint_name_ptr != 0) &&
            (msg_type == SN_NSDL_EP_REGISTER_MESSAGE)) {
        /* fill endpoint name, first ?ep=, then endpoint name */
        memcpy(temp_ptr, ep_name_parameter_string, sizeof(ep_name_parameter_string));
        temp_ptr += EP_NAME_PARAMETERS_LEN;
        memcpy(temp_ptr, parameter_ptr->endpoint_name_ptr, parameter_ptr->endpoint_name_len);
        temp_ptr += parameter_ptr->endpoint_name_len;
    }

    /******************************************************/
    /* If endpoint type is configured, fill needed fields */
    /******************************************************/

    if ((parameter_ptr->type_len != 0) &&
            (parameter_ptr->type_ptr != 0) &&
            (msg_type == SN_NSDL_EP_REGISTER_MESSAGE || msg_type == SN_NSDL_EP_UPDATE_MESSAGE)) {
        if (temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr) {
            *temp_ptr++ = '&';
        }

        memcpy(temp_ptr, et_parameter, sizeof(et_parameter));
        temp_ptr += ET_PARAMETER_LEN;
        memcpy(temp_ptr, parameter_ptr->type_ptr, parameter_ptr->type_len);
        temp_ptr += parameter_ptr->type_len;
    }


    /******************************************************/
    /* If lifetime is configured, fill needed fields */
    /******************************************************/

    if ((parameter_ptr->lifetime_len != 0) && (parameter_ptr->lifetime_ptr != 0)) {
        if (temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr) {
            *temp_ptr++ = '&';
        }

        memcpy(temp_ptr, ep_lifetime_parameter, sizeof(ep_lifetime_parameter));
        temp_ptr += LT_PARAMETER_LEN;
        memcpy(temp_ptr, parameter_ptr->lifetime_ptr, parameter_ptr->lifetime_len);
        temp_ptr += parameter_ptr->lifetime_len;
    }

    /******************************************************/
    /* If version is configured, fill needed fields */
    /******************************************************/

    if ((parameter_ptr->version_len != 0) && (msg_type == SN_NSDL_EP_REGISTER_MESSAGE) &&
            (parameter_ptr->version_ptr != 0)) {
        if (temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr) {
            *temp_ptr++ = '&';
        }

        memcpy(temp_ptr, version_parameter, sizeof(version_parameter));
        temp_ptr += VERSION_PARAMETER_LEN;
        memcpy(temp_ptr, parameter_ptr->version_ptr, parameter_ptr->version_len);
        temp_ptr += parameter_ptr->version_len;
    }

    /******************************************************/
    /* If domain is configured, fill needed fields */
    /******************************************************/

    if ((parameter_ptr->domain_name_len != 0) &&
            (parameter_ptr->domain_name_ptr != 0) &&
            (msg_type == SN_NSDL_EP_REGISTER_MESSAGE)) {
        if (temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr) {
            *temp_ptr++ = '&';
        }

        memcpy(temp_ptr, ep_domain_parameter, sizeof(ep_domain_parameter));
        temp_ptr += DOMAIN_PARAMETER_LEN;
        memcpy(temp_ptr, parameter_ptr->domain_name_ptr, parameter_ptr->domain_name_len);
        temp_ptr += parameter_ptr->domain_name_len;
    }

    /******************************************************/
    /* If queue-mode is configured, fill needed fields    */
    /******************************************************/

    if (((parameter_ptr->binding_and_mode & 0x01) ||
            (parameter_ptr->binding_and_mode & 0x04)) &&
            (msg_type == SN_NSDL_EP_REGISTER_MESSAGE)) {
        if (temp_ptr != source_msg_ptr->options_list_ptr->uri_query_ptr) {
            *temp_ptr++ = '&';
        }

        memcpy(temp_ptr, bs_queue_mode, sizeof(bs_queue_mode));
        temp_ptr += BS_QUEUE_MODE_PARAMETER_LEN;

        if (parameter_ptr->binding_and_mode & 0x01) {
            *temp_ptr++ = 'U';
            if (parameter_ptr->binding_and_mode & 0x02) {
                *temp_ptr++ = 'Q';
            }
        }

        if (parameter_ptr->binding_and_mode & 0x04) {
            *temp_ptr++ = 'S';
            if ((parameter_ptr->binding_and_mode & 0x02) && !(parameter_ptr->binding_and_mode & 0x01)) {
                *temp_ptr++ = 'Q';
            }
        }
    }

    if (uri_query) {
        memcpy(temp_ptr, uri_query, strlen(uri_query));
    }

    return SN_NSDL_SUCCESS;
}

static bool validateParameters(sn_nsdl_ep_parameters_s *parameter_ptr)
{
    if (!validate(parameter_ptr->domain_name_ptr, parameter_ptr->domain_name_len, '&')) {
        return false;
    }

    if (!validate(parameter_ptr->endpoint_name_ptr, parameter_ptr->endpoint_name_len, '&')) {
        return false;
    }

    if (!validate(parameter_ptr->lifetime_ptr, parameter_ptr->lifetime_len, '&')) {
        return false;
    }

    if (!validate(parameter_ptr->version_ptr, parameter_ptr->version_len, '&')) {
        return false;
    }

    if (!validate(parameter_ptr->type_ptr, parameter_ptr->type_len, '&')) {
        return false;
    }
    return true;
}

static bool validate(uint8_t *ptr, uint32_t len, char illegalChar)
{
    if (ptr) {
        for (uint32_t i = 0; i < len; i++) {
            if (ptr[i] == illegalChar) {
                return false;
            }
        }
    }
    return true;
}

/**
 * \fn static int8_t sn_nsdl_local_rx_function(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr)
 *
 * \brief If received message is reply for the message that NSDL has been sent, it is processed here. Else, packet will be sent to application.
 * \param *handle           Pointer to nsdl-library handle
 * \param *coap_packet_ptr  Pointer to received CoAP packet
 * \param *address_ptr      Pointer to source address struct
 *
 * \return      SN_NSDL_SUCCESS = 0, Failed = -1
 */
static int8_t sn_nsdl_local_rx_function(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr)
{
    if ((coap_packet_ptr == 0) || (address_ptr == 0)) {
        return SN_NSDL_FAILURE;
    }

    bool is_reg_msg = false;
    bool is_update_reg_msg = false;
    bool is_unreg_msg = false;
    bool is_bs_msg = false;

    if (coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CREATED &&
            coap_packet_ptr->token_len == sizeof(handle->register_token) &&
            memcmp(coap_packet_ptr->token_ptr, &handle->register_token, coap_packet_ptr->token_len) == 0) {
        handle->sn_nsdl_endpoint_registered = SN_NSDL_ENDPOINT_IS_REGISTERED;
        sn_grs_mark_resources_as_registered(handle);
        is_reg_msg = true;
        int8_t ret = sn_nsdl_resolve_ep_information(handle, coap_packet_ptr);
        if (ret != SN_NSDL_SUCCESS) {
            return ret;
        }
    }

    else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CHANGED &&
             coap_packet_ptr->token_len == sizeof(handle->update_register_token) &&
             memcmp(coap_packet_ptr->token_ptr,
                    &handle->update_register_token,
                    coap_packet_ptr->token_len) == 0) {
        is_update_reg_msg = true;
    }

    else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_DELETED &&
             coap_packet_ptr->token_len == sizeof(handle->unregister_token) &&
             memcmp(coap_packet_ptr->token_ptr, &handle->unregister_token, coap_packet_ptr->token_len) == 0) {
        is_unreg_msg = true;
        handle->sn_nsdl_free(handle->ep_information_ptr->endpoint_name_ptr);
        handle->ep_information_ptr->endpoint_name_ptr = 0;
        handle->ep_information_ptr->endpoint_name_len = 0;

        handle->sn_nsdl_free(handle->ep_information_ptr->domain_name_ptr);
        handle->ep_information_ptr->domain_name_ptr = 0;
        handle->ep_information_ptr->domain_name_len = 0;
    }
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    else if (coap_packet_ptr->token_len == sizeof(handle->bootstrap_token) &&
             memcmp(coap_packet_ptr->token_ptr, &handle->bootstrap_token, coap_packet_ptr->token_len) == 0) {
        is_bs_msg = true;
    }
#endif

    /* Store the current message token so that we can identify if same operation was initiated from callback */
    uint32_t temp_token = 0;
    if (is_reg_msg) {
        temp_token = handle->register_token;
    } else if (is_unreg_msg) {
        temp_token = handle->unregister_token;
    } else if (is_update_reg_msg) {
        temp_token = handle->update_register_token;
    }
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    else if (is_bs_msg) {
        temp_token = handle->bootstrap_token;
    }
#endif

    /* No messages to wait for, or message was not response to our request */
    int ret = handle->sn_nsdl_rx_callback(handle, coap_packet_ptr, address_ptr);

    /* If callback initiated same operation then token is updated in handle and temp_token won't match.
       This means we don't clear the handle token here because we will wait for response to new request. */
    if (is_reg_msg && temp_token == handle->register_token) {
        handle->register_token = 0;
    } else if (is_unreg_msg && temp_token == handle->unregister_token) {
        handle->unregister_token = 0;
    } else if (is_update_reg_msg && temp_token == handle->update_register_token) {
        handle->update_register_token = 0;
    }
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    else if (is_bs_msg && temp_token == handle->bootstrap_token) {
        handle->bootstrap_token = 0;
    }
#endif
    return ret;
}

/**
 * \fn static int8_t sn_nsdl_resolve_ep_information(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr)
 *
 *
 * \brief Resolves endpoint information from received CoAP message
 * \param *handle           Pointer to nsdl-library handle
 * \param *coap_packet_ptr  Pointer to received CoAP message
 *
 * \return  SN_NSDL_SUCCESS = 0, Failed < 0
 */
static int8_t sn_nsdl_resolve_ep_information(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr)
{
    uint8_t     *temp_ptr;
    uint8_t     parameter_count     = 0;
    uint16_t    parameter_len       = 0;

    if (!coap_packet_ptr || !coap_packet_ptr->options_list_ptr ||
            !coap_packet_ptr->options_list_ptr->location_path_ptr) {
        return SN_NSDL_FAILURE;
    }

    temp_ptr = coap_packet_ptr->options_list_ptr->location_path_ptr;

    while (temp_ptr <= (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len)) {

        if ((temp_ptr == (coap_packet_ptr->options_list_ptr->location_path_ptr + coap_packet_ptr->options_list_ptr->location_path_len)) || (*temp_ptr == '/')) {

            parameter_count++;
            if (parameter_count == 2) {
                if (!handle->ep_information_ptr->domain_name_ptr) {
                    handle->ep_information_ptr->domain_name_len = parameter_len - 1;
                    handle->ep_information_ptr->domain_name_ptr = handle->sn_nsdl_alloc(handle->ep_information_ptr->domain_name_len);
                    if (!handle->ep_information_ptr->domain_name_ptr) {
                        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
                    }
                    memcpy(handle->ep_information_ptr->domain_name_ptr, temp_ptr - handle->ep_information_ptr->domain_name_len, handle->ep_information_ptr->domain_name_len);
                }

            }
            if (parameter_count == 3) {
                if (!handle->ep_information_ptr->endpoint_name_ptr) {
                    handle->ep_information_ptr->endpoint_name_len = parameter_len - 1;
                    handle->ep_information_ptr->endpoint_name_ptr = handle->sn_nsdl_alloc(handle->ep_information_ptr->endpoint_name_len);
                    if (!handle->ep_information_ptr->endpoint_name_ptr) {
                        if (handle->ep_information_ptr->domain_name_ptr) {
                            handle->sn_nsdl_free(handle->ep_information_ptr->domain_name_ptr);
                            handle->ep_information_ptr->domain_name_ptr = NULL;
                            handle->ep_information_ptr->domain_name_len = 0;
                        }

                        return SN_NSDL_MEMORY_ALLOCATION_FAILED;

                    }
                    memcpy(handle->ep_information_ptr->endpoint_name_ptr, temp_ptr - handle->ep_information_ptr->endpoint_name_len, handle->ep_information_ptr->endpoint_name_len);
                }
            }
            parameter_len = 0;
        }
        parameter_len++;
        temp_ptr++;
    }


    return SN_NSDL_SUCCESS;
}

extern int8_t set_NSP_address(struct nsdl_s *handle, uint8_t *NSP_address, uint8_t address_length, uint16_t port, sn_nsdl_addr_type_e address_type)
{
    /* Check parameters and source pointers */
    if (!handle || !NSP_address) {
        return SN_NSDL_FAILURE;
    }

    handle->server_address.type = address_type;

    handle->sn_nsdl_free(handle->server_address.addr_ptr);

    handle->server_address.addr_len = address_length;

    handle->server_address.addr_ptr = handle->sn_nsdl_alloc(handle->server_address.addr_len);
    if (!handle->server_address.addr_ptr) {
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    memcpy(handle->server_address.addr_ptr, NSP_address, handle->server_address.addr_len);
    handle->server_address.port = port;

    return SN_NSDL_SUCCESS;
}


static uint8_t sn_nsdl_itoa_len(uint32_t value)
{
    uint8_t i = 0;

    do {
        i++;
    } while ((value /= 10) > 0);

    return i;
}

static uint8_t *sn_nsdl_itoa(uint8_t *ptr, uint32_t value)
{

    uint8_t start = 0;
    uint8_t end = 0;
    uint8_t i;

    i = 0;

    /* ITOA */
    do {
        ptr[i++] = (value % 10) + '0';
    } while ((value /= 10) > 0);

    end = i - 1;

    /* reverse (part of ITOA) */
    while (start < end) {
        uint8_t chr;

        chr = ptr[start];
        ptr[start] = ptr[end];
        ptr[end] = chr;

        start++;
        end--;

    }
    return (ptr + i);
}

static int8_t set_endpoint_info(struct nsdl_s *handle, sn_nsdl_ep_parameters_s *endpoint_info_ptr)
{
    handle->sn_nsdl_free(handle->ep_information_ptr->domain_name_ptr);
    handle->ep_information_ptr->domain_name_ptr = 0;
    handle->ep_information_ptr->domain_name_len = 0;

    handle->sn_nsdl_free(handle->ep_information_ptr->endpoint_name_ptr);
    handle->ep_information_ptr->endpoint_name_ptr = 0;
    handle->ep_information_ptr->endpoint_name_len = 0;

    handle->sn_nsdl_free(handle->ep_information_ptr->type_ptr);
    handle->ep_information_ptr->type_ptr = 0;
    handle->ep_information_ptr->type_len = 0;

    if (endpoint_info_ptr->domain_name_ptr && endpoint_info_ptr->domain_name_len) {
        handle->ep_information_ptr->domain_name_ptr = handle->sn_nsdl_alloc(endpoint_info_ptr->domain_name_len);

        if (!handle->ep_information_ptr->domain_name_ptr) {
            return SN_NSDL_FAILURE;
        }

        memcpy(handle->ep_information_ptr->domain_name_ptr, endpoint_info_ptr->domain_name_ptr, endpoint_info_ptr->domain_name_len);
        handle->ep_information_ptr->domain_name_len = endpoint_info_ptr->domain_name_len;
    }

    if (endpoint_info_ptr->endpoint_name_ptr && endpoint_info_ptr->endpoint_name_len) {
        handle->ep_information_ptr->endpoint_name_ptr = handle->sn_nsdl_alloc(endpoint_info_ptr->endpoint_name_len);

        if (!handle->ep_information_ptr->endpoint_name_ptr) {
            handle->sn_nsdl_free(handle->ep_information_ptr->domain_name_ptr);
            handle->ep_information_ptr->domain_name_ptr = 0;
            handle->ep_information_ptr->domain_name_len = 0;
            return SN_NSDL_FAILURE;
        }

        memcpy(handle->ep_information_ptr->endpoint_name_ptr, endpoint_info_ptr->endpoint_name_ptr, endpoint_info_ptr->endpoint_name_len);
        handle->ep_information_ptr->endpoint_name_len = endpoint_info_ptr->endpoint_name_len;
    }

    if (endpoint_info_ptr->type_ptr && endpoint_info_ptr->type_len) {
        handle->ep_information_ptr->type_ptr = handle->sn_nsdl_alloc(endpoint_info_ptr->type_len);
        if (handle->ep_information_ptr->type_ptr) {
            memcpy(handle->ep_information_ptr->type_ptr, endpoint_info_ptr->type_ptr, endpoint_info_ptr->type_len);
            handle->ep_information_ptr->type_len = endpoint_info_ptr->type_len;
        }
    }

    handle->ep_information_ptr->binding_and_mode = endpoint_info_ptr->binding_and_mode;
    handle->ep_information_ptr->ds_register_mode = endpoint_info_ptr->ds_register_mode;

    return SN_NSDL_SUCCESS;
}

extern int8_t sn_nsdl_send_coap_message(struct nsdl_s *handle, sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    return sn_grs_send_coap_message(handle, address_ptr, coap_hdr_ptr);
}

extern int8_t sn_nsdl_handle_block2_response_internally(struct nsdl_s *handle, uint8_t build_response)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    return sn_coap_protocol_handle_block2_response_internally(handle->grs->coap, build_response);
}

extern int8_t sn_nsdl_clear_coap_sent_blockwise_messages(struct nsdl_s *handle)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    // Enable function once new CoAP API is released to mbed-os
    sn_coap_protocol_clear_sent_blockwise_messages(handle->grs->coap);

    return SN_NSDL_SUCCESS;
}

extern int8_t sn_nsdl_clear_coap_received_blockwise_messages(struct nsdl_s *handle)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    sn_coap_protocol_clear_received_blockwise_messages(handle->grs->coap);

    return SN_NSDL_SUCCESS;
}

extern int32_t sn_nsdl_send_request(struct nsdl_s *handle,
                                    const sn_coap_msg_code_e msg_code,
                                    const char *uri_path,
                                    const uint32_t token,
                                    const size_t offset,
                                    const uint16_t payload_len,
                                    uint8_t *payload_ptr,
                                    DownloadType type)
{
    sn_coap_hdr_s  req_message;
    int32_t        message_id;

    if (handle == NULL || uri_path == NULL) {
        return SN_NSDL_FAILURE;
    }

    memset(&req_message, 0, sizeof(sn_coap_hdr_s));

    // Fill message fields
    req_message.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    req_message.msg_code = msg_code;

    // In GET we use hardcoded uri path('fw' or 'download') since the actual binary path will be part of
    // proxy uri option
    if (req_message.msg_code == COAP_MSG_CODE_REQUEST_GET) {
        if (type == FIRMWARE_DOWNLOAD) {
            req_message.uri_path_len = FIRMWARE_DOWNLOAD_LEN;
            req_message.uri_path_ptr = firmware_download_uri;
        } else {
            req_message.uri_path_len = GENERIC_DOWNLOAD_LEN;
            req_message.uri_path_ptr = generic_download_uri;
        }
    } else {
        req_message.uri_path_len = (uint16_t)strlen(uri_path);
        req_message.uri_path_ptr = (uint8_t *)uri_path;
    }
    req_message.token_ptr = (uint8_t *)&token;
    req_message.token_len = sizeof(token);
    if (msg_code == COAP_MSG_CODE_REQUEST_POST || msg_code == COAP_MSG_CODE_REQUEST_PUT) {
        // Use payload only if POST or PUT request
        req_message.payload_ptr = payload_ptr;
        req_message.payload_len = payload_len;
    }

    if (sn_coap_parser_alloc_options(handle->grs->coap, &req_message) == NULL) {
        handle->grs->coap->sn_coap_protocol_free(req_message.options_list_ptr);
        return SN_NSDL_MEMORY_ALLOCATION_FAILED;
    }

    if (msg_code == COAP_MSG_CODE_REQUEST_GET) {
        req_message.options_list_ptr->proxy_uri_len = (uint16_t)strlen(uri_path);
        req_message.options_list_ptr->proxy_uri_ptr = (uint8_t *)uri_path;
    }

// Skip block options if feature is not enabled
#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    // Add block number
    req_message.options_list_ptr->block2 = 0;
    if (offset > 0) {
        req_message.options_list_ptr->block2 = ((offset / handle->grs->coap->sn_coap_block_data_size) << 4);
    }
    // Add block size
    req_message.options_list_ptr->block2 |= sn_coap_convert_block_size(handle->grs->coap->sn_coap_block_data_size);
#else
    (void)offset;
#endif

    // Build and send coap message
    message_id = sn_nsdl_internal_coap_send(handle, &req_message, &handle->server_address);
    handle->grs->coap->sn_coap_protocol_free(req_message.options_list_ptr);

    return message_id;
}

extern int8_t sn_nsdl_put_resource(struct nsdl_s *handle, sn_nsdl_dynamic_resource_parameters_s *res)
{
    if (!handle) {
        return SN_NSDL_FAILURE;
    }

    return sn_grs_put_resource(handle->grs, res);
}

extern int8_t sn_nsdl_pop_resource(struct nsdl_s *handle, sn_nsdl_dynamic_resource_parameters_s *res)
{
    if (!handle) {
        return SN_NSDL_FAILURE;
    }

    return sn_grs_pop_resource(handle->grs, res);
}

extern int8_t sn_nsdl_delete_resource(struct nsdl_s *handle, const char *path)
{
    /* Check parameters */
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }

    return sn_grs_delete_resource(handle->grs, path);
}
extern const sn_nsdl_dynamic_resource_parameters_s *sn_nsdl_get_first_resource(struct nsdl_s *handle)
{
    /* Check parameters */
    if (handle == NULL) {
        return NULL;
    }

    return sn_grs_get_first_resource(handle->grs);
}
extern const sn_nsdl_dynamic_resource_parameters_s *sn_nsdl_get_next_resource(struct nsdl_s *handle, const sn_nsdl_dynamic_resource_parameters_s *resource)
{
    /* Check parameters */
    if (handle == NULL) {
        return NULL;
    }

    return sn_grs_get_next_resource(handle->grs, resource);
}

extern sn_coap_hdr_s *sn_nsdl_build_response(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code)
{
    if (handle == NULL) {
        return NULL;
    }

    return sn_coap_build_response(handle->grs->coap, coap_packet_ptr, msg_code);
}

extern sn_coap_options_list_s *sn_nsdl_alloc_options_list(struct nsdl_s *handle, sn_coap_hdr_s *coap_msg_ptr)
{
    if (handle == NULL || coap_msg_ptr == NULL) {
        return NULL;
    }
    return sn_coap_parser_alloc_options(handle->grs->coap, coap_msg_ptr);
}

extern void sn_nsdl_release_allocated_coap_msg_mem(struct nsdl_s *handle, sn_coap_hdr_s *freed_coap_msg_ptr)
{
    if (handle == NULL) {
        return;
    }

    sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap, freed_coap_msg_ptr);
}

extern int8_t sn_nsdl_set_retransmission_parameters(struct nsdl_s *handle,
                                                    uint8_t resending_count, uint8_t resending_interval)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }
    return sn_coap_protocol_set_retransmission_parameters(handle->grs->coap,
                                                          resending_count, resending_interval);
}

extern int8_t sn_nsdl_set_retransmission_buffer(struct nsdl_s *handle,
                                                uint8_t buffer_size_messages, uint16_t buffer_size_bytes)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }
    return sn_coap_protocol_set_retransmission_buffer(handle->grs->coap,
                                                      buffer_size_messages, buffer_size_bytes);
}

extern int8_t sn_nsdl_set_block_size(struct nsdl_s *handle, uint16_t block_size)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }
    return sn_coap_protocol_set_block_size(handle->grs->coap, block_size);
}

extern int8_t sn_nsdl_set_duplicate_buffer_size(struct nsdl_s *handle, uint8_t message_count)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }
    return sn_coap_protocol_set_duplicate_buffer_size(handle->grs->coap, message_count);
}

bool sn_nsdl_check_uint_overflow(uint16_t resource_size, uint16_t param_a, uint16_t param_b)
{
    uint16_t first_check = param_a + param_b;
    if (first_check < param_b) {
        return false;
    } else {
        uint16_t total = resource_size + first_check;
        if (total < first_check) {
            return false;
        } else {
            return true;
        }
    }
}

extern int8_t sn_nsdl_set_context(struct nsdl_s *const handle, void *const context)
{
    if (handle == NULL) {
        return SN_NSDL_FAILURE;
    }
    handle->context = context;
    return SN_NSDL_SUCCESS;
}

extern void *sn_nsdl_get_context(const struct nsdl_s *const handle)
{
    if (handle == NULL) {
        return NULL;
    }
    return handle->context;
}

int8_t sn_nsdl_clear_coap_resending_queue(struct nsdl_s *handle)
{
    if (handle == NULL || handle->grs == NULL) {
        tr_err("sn_nsdl_clear_coap_resending_queue failed.");
        return SN_NSDL_FAILURE;
    }
    sn_coap_protocol_clear_retransmission_buffer(handle->grs->coap);
    return SN_NSDL_SUCCESS;
}

int8_t sn_nsdl_remove_msg_from_retransmission(struct nsdl_s *handle, uint8_t *token, uint8_t token_len)
{
    if (handle == NULL || handle->grs == NULL || handle->grs->coap == NULL || token == NULL || token_len == 0) {
        tr_err("sn_nsdl_remove_msg_from_retransmission failed.");
        return SN_NSDL_FAILURE;
    }

#if ENABLE_RESENDINGS

    return sn_coap_protocol_delete_retransmission_by_token(handle->grs->coap, token, token_len);
#else
    return SN_NSDL_FAILURE;
#endif
}

#ifdef RESOURCE_ATTRIBUTES_LIST
static void sn_nsdl_free_attribute_value(sn_nsdl_attribute_item_s *attribute)
{
    switch (attribute->attribute_name) {
        case ATTR_RESOURCE_TYPE:
        case ATTR_INTERFACE_DESCRIPTION:
        case ATTR_ENDPOINT_NAME:
            free(attribute->value);
            attribute->value = NULL;
            break;
        case ATTR_NOP:
        case ATTR_END:
        default:
            break;
    }
}

void sn_nsdl_free_resource_attributes_list(sn_nsdl_static_resource_parameters_s *params)
{
    if (params == NULL || params->free_on_delete == false) {
        return;
    }
    sn_nsdl_attribute_item_s *item = params->attributes_ptr;
    if (item) {
        while (item->attribute_name != ATTR_END) {
            sn_nsdl_free_attribute_value(item);
            item++;
        }
        free(params->attributes_ptr);
        params->attributes_ptr = NULL;
    }
}

bool sn_nsdl_set_resource_attribute(sn_nsdl_static_resource_parameters_s *params, const sn_nsdl_attribute_item_s *attribute)
{
    if (params == NULL || params->free_on_delete == false) {
        return false;
    }
    unsigned int item_count = 0;
    sn_nsdl_attribute_item_s *item = params->attributes_ptr;
    // Count the number of attributes for reallocation, update in place though
    // if the attribute already existed
    while (item != NULL) {
        item_count++;
        if (item->attribute_name == ATTR_END) {
            break;
        }
        // Check if attribute already exists or if there is NOP we can overwrite
        if (item->attribute_name == attribute->attribute_name || item->attribute_name == ATTR_NOP) {
            // Found attribute or NOP, overwrite it
            sn_nsdl_free_attribute_value(item);
            item->attribute_name = attribute->attribute_name;
            item->value = attribute->value;
            return true;
        }
        item++;
    }
    // Attribute did not yet exist (ptr was null or ATTR_END was first one)
    if (item_count > 0) {
        // List already had some attributes, so reallocate
        size_t new_size = (item_count + 1) * sizeof(sn_nsdl_attribute_item_s);
        item = params->attributes_ptr;
        params->attributes_ptr = realloc(item, new_size);
        if (params->attributes_ptr == NULL) {
            // realloc failed, put back original pointer and return false
            params->attributes_ptr = item;
            return false;
        }
        // And move item ptr to ATTR_END to update that and last attribute
        item = &(params->attributes_ptr[item_count - 1]);
    } else {
        // No attributes, so allocate first time (1 struct for attribute and 1 struct for ATTR_END)
        params->attributes_ptr = (char *)malloc(2 * sizeof(sn_nsdl_attribute_item_s));
        if (params->attributes_ptr == NULL) {
            return false;
        }
        item = params->attributes_ptr;
    }
    item->attribute_name = attribute->attribute_name;
    item->value = attribute->value;
    item++;
    item->attribute_name = ATTR_END;
    item->value = NULL;
    return true;
}

const char *sn_nsdl_get_resource_attribute(const sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute_name)
{
    char *value = NULL;
    if (params != NULL) {
        sn_nsdl_attribute_item_s *item = params->attributes_ptr;
        while (item != NULL && item->attribute_name != ATTR_END) {
            if (item->attribute_name == attribute_name) {
                value = item->value;
                break;
            }
            item++;
        }
    }
    return value;
}

bool sn_nsdl_remove_resource_attribute(sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute_name)
{
    if (params == NULL || params->free_on_delete == false) {
        return false;
    }

    bool found = false;
    sn_nsdl_attribute_item_s *item = params->attributes_ptr;
    while (item != NULL) {
        if (item->attribute_name == ATTR_END) {
            break;
        }
        // Remove if attribute name matches
        if (item->attribute_name == attribute_name) {
            // Currently only pointer values, need to free and set as NOP
            sn_nsdl_free_attribute_value(item);
            item->attribute_name = ATTR_NOP;
            found = true;
            break;
        }
        item++;
    }

    return found;

}

#endif


void sn_nsdl_print_coap_data(sn_coap_hdr_s *coap_header_ptr, bool outgoing)
{
#if MBED_CONF_MBED_TRACE_ENABLE
    if (!coap_header_ptr) {
        return;
    }

    if (outgoing) {
        tr_info("======== Outgoing CoAP package ========");
    } else {
        tr_info("======== Incoming CoAP package ========");
    }

    if (coap_header_ptr->uri_path_len > 0 && coap_header_ptr->uri_path_ptr) {
        tr_info("Uri-Path:\t\t%.*s", coap_header_ptr->uri_path_len, coap_header_ptr->uri_path_ptr);
    }
    tr_info("Status:\t\t%s", sn_nsdl_coap_status_description(coap_header_ptr->coap_status));
    tr_info("Code:\t\t%s", sn_nsdl_coap_message_code_desc(coap_header_ptr->msg_code));
    tr_info("Type:\t\t%s", sn_nsdl_coap_message_type_desc(coap_header_ptr->msg_type));
    tr_info("Id:\t\t%d", coap_header_ptr->msg_id);
    if (coap_header_ptr->token_ptr && coap_header_ptr->token_len > 0) {
        tr_info("Token:\t\t%s", tr_array(coap_header_ptr->token_ptr, coap_header_ptr->token_len));
    }
    if (coap_header_ptr->content_format != -1) {
        tr_info("Content-type:\t%d", coap_header_ptr->content_format);
    }
    tr_info("Payload len:\t%d", coap_header_ptr->payload_len);
#ifdef MBED_CLIENT_PRINT_COAP_PAYLOAD
    if (coap_header_ptr->payload_ptr && coap_header_ptr->payload_len > 0) {
        int i = 0;
        int row_len = 32;
        int max_length = 2048;
        while (i < coap_header_ptr->payload_len && i < max_length) {
            if (i + row_len > coap_header_ptr->payload_len) {
                row_len = coap_header_ptr->payload_len - i;
            }
            tr_info("PL:\t\t%s", tr_array(coap_header_ptr->payload_ptr + i, row_len));
            i += row_len;
        }
        if (i >= max_length) {
            tr_info("PL:\t\t.....");
        }
    }
#endif

    if (coap_header_ptr->options_list_ptr) {
        if (coap_header_ptr->options_list_ptr->etag_ptr && coap_header_ptr->options_list_ptr->etag_len > 0) {
            tr_info("E-tag:\t%s", tr_array(coap_header_ptr->options_list_ptr->etag_ptr, coap_header_ptr->options_list_ptr->etag_len));
        }
        if (coap_header_ptr->options_list_ptr->proxy_uri_ptr && coap_header_ptr->options_list_ptr->proxy_uri_len > 0) {
            tr_info("Proxy uri:\t%.*s", coap_header_ptr->options_list_ptr->proxy_uri_len, coap_header_ptr->options_list_ptr->proxy_uri_ptr);
        }

        if (coap_header_ptr->options_list_ptr->uri_host_ptr && coap_header_ptr->options_list_ptr->uri_host_len > 0) {
            tr_info("Uri host:\t%.*s", coap_header_ptr->options_list_ptr->uri_host_len, coap_header_ptr->options_list_ptr->uri_host_ptr);
        }

        if (coap_header_ptr->options_list_ptr->location_path_ptr && coap_header_ptr->options_list_ptr->location_path_len > 0) {
            tr_info("Location path:\t%.*s", coap_header_ptr->options_list_ptr->location_path_len, coap_header_ptr->options_list_ptr->location_path_ptr);
        }

        if (coap_header_ptr->options_list_ptr->location_query_ptr && coap_header_ptr->options_list_ptr->location_query_len > 0) {
            tr_info("Location query:\t%.*s", coap_header_ptr->options_list_ptr->location_query_len, coap_header_ptr->options_list_ptr->location_query_ptr);
        }

        if (coap_header_ptr->options_list_ptr->uri_query_ptr && coap_header_ptr->options_list_ptr->uri_query_len > 0) {
            tr_info("Uri query:\t%.*s", coap_header_ptr->options_list_ptr->uri_query_len, coap_header_ptr->options_list_ptr->uri_query_ptr);
        }

        tr_info("Max-age:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->max_age);
        if (coap_header_ptr->options_list_ptr->use_size1) {
            tr_info("Size 1:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->size1);
        }
        if (coap_header_ptr->options_list_ptr->use_size2) {
            tr_info("Size 2:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->size2);
        }
        if (coap_header_ptr->options_list_ptr->accept != -1) {
            tr_info("Accept:\t\t%d", coap_header_ptr->options_list_ptr->accept);
        }
        if (coap_header_ptr->options_list_ptr->uri_port != -1) {
            tr_info("Uri port:\t%" PRId32"", coap_header_ptr->options_list_ptr->uri_port);
        }
        if (coap_header_ptr->options_list_ptr->observe != -1) {
            tr_info("Observe:\t\t%" PRId32"", coap_header_ptr->options_list_ptr->observe);
        }
        if (coap_header_ptr->options_list_ptr->block1 != -1) {
            tr_info("Block1 number:\t%" PRId32"", coap_header_ptr->options_list_ptr->block1 >> 4);
            uint8_t temp = (coap_header_ptr->options_list_ptr->block1 & 0x07);
            uint16_t block_size = 1u << (temp + 4);
            tr_info("Block1 size:\t%d", block_size);
            tr_info("Block1 more:\t%d", (coap_header_ptr->options_list_ptr->block1) & 0x08 ? true : false);
        }
        if (coap_header_ptr->options_list_ptr->block2 != -1) {
            tr_info("Block2 number:\t%" PRId32"", coap_header_ptr->options_list_ptr->block2 >> 4);
            uint8_t temp = (coap_header_ptr->options_list_ptr->block2 & 0x07);
            uint16_t block_size = 1u << (temp + 4);
            tr_info("Block2 size:\t%d", block_size);
            tr_info("Block2 more:\t%d", (coap_header_ptr->options_list_ptr->block2) & 0x08 ? true : false);
        }
    }
    tr_info("======== End of CoAP package ========");
#else
    (void) coap_header_ptr;
    (void) outgoing;
#endif
}

#if MBED_CONF_MBED_TRACE_ENABLE
const char *sn_nsdl_coap_status_description(sn_coap_status_e status)
{
    switch (status) {
        case COAP_STATUS_OK:
            return "COAP_STATUS_OK";
        case COAP_STATUS_PARSER_ERROR_IN_HEADER:
            return "COAP_STATUS_PARSER_ERROR_IN_HEADER";
        case COAP_STATUS_PARSER_DUPLICATED_MSG:
            return "COAP_STATUS_PARSER_DUPLICATED_MSG";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING:
            return "COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING";
        case COAP_STATUS_PARSER_BLOCKWISE_ACK:
            return "COAP_STATUS_PARSER_BLOCKWISE_ACK";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_REJECTED:
            return "COAP_STATUS_PARSER_BLOCKWISE_MSG_REJECTED";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED:
            return "COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED";
        case COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED:
            return "COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED";
        default:
            return "";
    }
}

const char *sn_nsdl_coap_message_code_desc(int msg_code)
{
    switch (msg_code) {
        case COAP_MSG_CODE_EMPTY:
            return "COAP_MSG_CODE_EMPTY";
        case COAP_MSG_CODE_REQUEST_GET:
            return "COAP_MSG_CODE_REQUEST_GET";
        case COAP_MSG_CODE_REQUEST_POST:
            return "COAP_MSG_CODE_REQUEST_POST";
        case COAP_MSG_CODE_REQUEST_PUT:
            return "COAP_MSG_CODE_REQUEST_PUT";
        case COAP_MSG_CODE_REQUEST_DELETE:
            return "COAP_MSG_CODE_REQUEST_DELETE";
        case COAP_MSG_CODE_RESPONSE_CREATED:
            return "COAP_MSG_CODE_RESPONSE_CREATED";
        case COAP_MSG_CODE_RESPONSE_DELETED:
            return "COAP_MSG_CODE_RESPONSE_DELETED";
        case COAP_MSG_CODE_RESPONSE_VALID:
            return "COAP_MSG_CODE_RESPONSE_VALID";
        case COAP_MSG_CODE_RESPONSE_CHANGED:
            return "COAP_MSG_CODE_RESPONSE_CHANGED";
        case COAP_MSG_CODE_RESPONSE_CONTENT:
            return "COAP_MSG_CODE_RESPONSE_CONTENT";
        case COAP_MSG_CODE_RESPONSE_CONTINUE:
            return "COAP_MSG_CODE_RESPONSE_CONTINUE";
        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
            return "COAP_MSG_CODE_RESPONSE_BAD_REQUEST";
        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
            return "COAP_MSG_CODE_RESPONSE_UNAUTHORIZED";
        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
            return "COAP_MSG_CODE_RESPONSE_BAD_OPTION";
        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
            return "COAP_MSG_CODE_RESPONSE_FORBIDDEN";
        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
            return "COAP_MSG_CODE_RESPONSE_NOT_FOUND";
        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
            return "COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED";
        case COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE:
            return "COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE";
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
            return "COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE";
        case COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED:
            return "COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED";
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
            return "COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE";
        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT:
            return "COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT";
        case COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR:
            return "COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR";
        case COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED:
            return "COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED";
        case COAP_MSG_CODE_RESPONSE_BAD_GATEWAY:
            return "COAP_MSG_CODE_RESPONSE_BAD_GATEWAY";
        case COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE:
            return "COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE";
        case COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT:
            return "COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT";
        case COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED:
            return "COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED";
        default:
            return "";
    }
}

const char *sn_nsdl_coap_message_type_desc(int msg_type)
{
    switch (msg_type) {
        case COAP_MSG_TYPE_CONFIRMABLE:
            return "COAP_MSG_TYPE_CONFIRMABLE";
        case COAP_MSG_TYPE_NON_CONFIRMABLE:
            return "COAP_MSG_TYPE_NON_CONFIRMABLE";
        case COAP_MSG_TYPE_ACKNOWLEDGEMENT:
            return "COAP_MSG_TYPE_ACKNOWLEDGEMENT";
        case COAP_MSG_TYPE_RESET:
            return "COAP_MSG_TYPE_RESET";
        default:
            return "";
    }
}
#endif

void remove_previous_block_data(struct nsdl_s *handle, sn_nsdl_addr_s *src_ptr, const uint32_t block_number)
{
#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    ns_list_foreach(coap_blockwise_payload_s, stored_payload_info_ptr, &handle->grs->coap->linked_list_blockwise_received_payloads) {
        uint32_t stored_number = stored_payload_info_ptr->block_number;
        // Remove the previous block data
        if (block_number - 1 == stored_number) {
            sn_coap_protocol_block_remove(handle->grs->coap,
                                          src_ptr,
                                          stored_payload_info_ptr->payload_len,
                                          stored_payload_info_ptr->payload_ptr);
            break;
        }
    }
#endif
}

bool update_last_block_data(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, bool block1)
{
    bool data_updated = false;
    // Whole message received --> pass only the last block data to application
    if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED) {
        // Get the block size
        uint8_t temp = 0;
        if (block1) {
            temp = (coap_packet_ptr->options_list_ptr->block1 & 0x07);
        } else {
            temp = (coap_packet_ptr->options_list_ptr->block2 & 0x07);
        }
        uint16_t block_size = 1u << (temp + 4);

        uint32_t new_payload_len = coap_packet_ptr->payload_len - block_size;
        uint8_t *temp_ptr =  handle->grs->coap->sn_coap_protocol_malloc(new_payload_len);
        if (temp_ptr) {
            // Skip the second last block data since it's still stored in mbed-coap list!
            memcpy(temp_ptr, coap_packet_ptr->payload_ptr + block_size, new_payload_len);
            handle->grs->coap->sn_coap_protocol_free(coap_packet_ptr->payload_ptr);
            coap_packet_ptr->payload_ptr = temp_ptr;
            coap_packet_ptr->payload_len = new_payload_len;
            data_updated = true;
        }
    }

    return data_updated;
}

static void sn_nsdl_add_token(struct nsdl_s *handle, uint32_t *token, sn_coap_hdr_s *message_ptr)
{
    handle->token_seed++;
    if (handle->token_seed == 0) {
        handle->token_seed++;
    }

    *token = handle->token_seed;

    message_ptr->token_ptr = (uint8_t *)token;
    message_ptr->token_len = sizeof(*token);
}

uint16_t sn_nsdl_get_block_size(const struct nsdl_s *handle)
{
    if (handle == NULL) {
        return 0;
    }

    return handle->grs->coap->sn_coap_block_data_size;
}

extern uint8_t sn_nsdl_get_retransmission_count(struct nsdl_s *handle)
{
#if ENABLE_RESENDINGS
    if (handle == NULL) {
        return 0;
    }

    return handle->grs->coap->sn_coap_resending_count;
#else
    (void) handle;
    return 0;
#endif
}

int32_t sn_nsdl_send_coap_ping(struct nsdl_s *handle)
{
    assert(handle);
    assert(handle->grs);

    sn_coap_hdr_s coap_ping = {0};

    /* Fill header */
    coap_ping.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    coap_ping.msg_code = COAP_MSG_CODE_EMPTY;
    coap_ping.content_format = COAP_CT_NONE;

    /* Send message */
    if (sn_nsdl_send_coap_message(handle, &handle->server_address, &coap_ping) >= SN_NSDL_SUCCESS) {
        return coap_ping.msg_id;
    }

    return SN_NSDL_FAILURE;
}

extern void sn_nsdl_remove_coap_block(struct nsdl_s *handle, sn_nsdl_addr_s *source_address, uint16_t payload_length, void *payload)
{
    /* Check parameters */
    if (handle == NULL) {
        return;
    }

    sn_coap_protocol_block_remove(handle->grs->coap, source_address, payload_length, payload);
}
