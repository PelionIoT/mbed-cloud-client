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
* \file sn_nsdl_lib.h
*
* \brief NanoService Devices Library header file
*
*
*/

#ifndef SN_NSDL_LIB_H_
#define SN_NSDL_LIB_H_

#include "ns_list.h"
#include "sn_client_config.h"
#include "mbed-client/m2mconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_NSDL_ENDPOINT_NOT_REGISTERED  0
#define SN_NSDL_ENDPOINT_IS_REGISTERED   1

#define MAX_TOKEN_SIZE 8
#define MAX_URI_QUERY_LEN 255

#if defined MBED_CONF_MBED_CLIENT_DISABLE_INTERFACE_DESCRIPTION
#define DISABLE_INTERFACE_DESCRIPTION MBED_CONF_MBED_CLIENT_DISABLE_INTERFACE_DESCRIPTION
#endif

#if defined MBED_CONF_MBED_CLIENT_DISABLE_RESOURCE_TYPE
#define DISABLE_RESOURCE_TYPE MBED_CONF_MBED_CLIENT_DISABLE_RESOURCE_TYPE
#endif

/* Handle structure */
struct nsdl_s;

/**
 * \brief Received device server security
 */
typedef enum omalw_server_security_ {
    SEC_NOT_SET = -1,
    PSK = 0,
    RPK = 1,
    CERTIFICATE = 2,
    NO_SEC = 3
} omalw_server_security_t;

/**
 * \brief Endpoint binding and mode
 */
typedef enum sn_nsdl_oma_binding_and_mode_ {
    BINDING_MODE_NOT_SET = 0,
    BINDING_MODE_U = 0x01,
    BINDING_MODE_Q = 0x02,
    BINDING_MODE_S = 0x04
} sn_nsdl_oma_binding_and_mode_t;

//#define RESOURCE_ATTRIBUTES_LIST
#ifdef RESOURCE_ATTRIBUTES_LIST
/*
 * \brief Resource attributes types
 */
typedef enum sn_nsdl_resource_attribute_ {
    ATTR_RESOURCE_TYPE,
    ATTR_INTERFACE_DESCRIPTION,
    ATTR_ENDPOINT_NAME,
    ATTR_QUEUE_MODE,
    ATTR_LIFETIME,
    ATTR_NOP,
    ATTR_END
} sn_nsdl_resource_attribute_t;

typedef struct sn_nsdl_attribute_item_ {
    sn_nsdl_resource_attribute_t attribute_name;
    char *value;
} sn_nsdl_attribute_item_s;

#endif

/**
 * \brief Endpoint registration mode.
 *      If REGISTER_WITH_RESOURCES, endpoint sends list of all resources during registration.
 *      If REGISTER_WITH_TEMPLATE, endpoint sends registration without resource list. Device server must have
 *      correctly configured template.
 */
typedef enum sn_nsdl_registration_mode_ {
    REGISTER_WITH_RESOURCES = 0,
    REGISTER_WITH_TEMPLATE
} sn_nsdl_registration_mode_t;

/**
 * \brief Endpoint registration parameters
 */
typedef struct sn_nsdl_ep_parameters_ {
    uint8_t     endpoint_name_len;
    uint8_t     domain_name_len;
    uint8_t     type_len;
    uint8_t     lifetime_len;
    uint8_t     location_len;
    uint8_t     version_len;

    sn_nsdl_registration_mode_t ds_register_mode;       /**< Defines registration mode */
    sn_nsdl_oma_binding_and_mode_t binding_and_mode;    /**< Defines endpoints binding and mode */

    uint8_t     *endpoint_name_ptr;                     /**< Endpoint name */
    uint8_t     *domain_name_ptr;                       /**< Domain to register. If null, NSP uses default domain */
    uint8_t     *type_ptr;                              /**< Endpoint type */
    uint8_t     *lifetime_ptr;                          /**< Endpoint lifetime in seconds. eg. "1200" = 1200 seconds */
    uint8_t     *location_ptr;                          /**< Endpoint location in server, optional parameter,default is NULL */
    uint8_t     *version_ptr;                           /**< OMA LWM2M version */
} sn_nsdl_ep_parameters_s;

/**
 * \brief Resource access rights
 */
typedef enum sn_grs_resource_acl_ {
    SN_GRS_GET_ALLOWED  = 0x01,
    SN_GRS_PUT_ALLOWED  = 0x02,
    SN_GRS_POST_ALLOWED = 0x04,
    SN_GRS_DELETE_ALLOWED   = 0x08
} sn_grs_resource_acl_e;

/**
 * \brief Defines the resource mode
 */
typedef enum sn_nsdl_resource_mode_ {
    SN_GRS_STATIC = 0,                  /**< Static resources have some value that doesn't change */
    SN_GRS_DYNAMIC,                     /**< Dynamic resources are handled in application. Therefore one must give function callback pointer to them */
    SN_GRS_DIRECTORY                    /**< Directory resources are unused and unsupported */
} sn_nsdl_resource_mode_e;

/**
 * Enum defining an different download types.
 * This is used for 'uri-path' when sending a GET request.
*/
typedef enum {
    FIRMWARE_DOWNLOAD = 0,
    GENERIC_DOWNLOAD
} DownloadType;

/**
 * \brief Defines static parameters for the resource.
 */
typedef struct sn_nsdl_static_resource_parameters_ {
#ifndef RESOURCE_ATTRIBUTES_LIST
#ifndef DISABLE_RESOURCE_TYPE
    char        *resource_type_ptr;         /**< Type of the resource */
#endif
#ifndef DISABLE_INTERFACE_DESCRIPTION
    char        *interface_description_ptr; /**< Interface description */
#endif
#else
    sn_nsdl_attribute_item_s *attributes_ptr;
#endif
    char        *path;                      /**< Resource path */
    bool        external_memory_block: 1;    /**< 0 means block messages are handled inside this library,
                                                 otherwise block messages are passed to application */
    unsigned    mode: 2;                    /**< STATIC etc.. */
    bool        free_on_delete: 1;          /**< 1 if struct is dynamic allocted --> to be freed */
} sn_nsdl_static_resource_parameters_s;

/**
 * \brief Defines dynamic parameters for the resource.
 */
typedef struct sn_nsdl_resource_parameters_ {
    uint8_t (*sn_grs_dyn_res_callback)(struct nsdl_s *,
                                       sn_coap_hdr_s *,
                                       sn_nsdl_addr_s *,
                                       sn_nsdl_capab_e);
#ifdef MEMORY_OPTIMIZED_API
    const sn_nsdl_static_resource_parameters_s  *static_resource_parameters;
#else
    sn_nsdl_static_resource_parameters_s        *static_resource_parameters;
#endif
    uint8_t                                     *resource;           /**< NULL if dynamic resource */
    ns_list_link_t                              link;
    uint16_t                                    resource_len;        /**< 0 if dynamic resource, resource information in static resource */
    uint16_t                                    coap_content_type;   /**< CoAP content type */
    unsigned                                    access: 4;            /**< Allowed operation mode, GET, PUT, etc,
                                                                         TODO! This should be in static struct but current
                                                                         mbed-client implementation requires this to be changed at runtime */
    unsigned                                    registered: 2;       /**< Is resource registered or not */
    bool                                        publish_uri: 1;      /**< 1 if resource to be published to server */
    bool                                        free_on_delete: 1;   /**< 1 if struct is dynamic allocted --> to be freed */
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    bool                                        observable: 1;       /**< Is resource observable or not */
#endif
    bool                                        auto_observable: 1;  /**< Is resource auto observable or not */
    bool                                        always_publish: 1;   /**< 1 if resource should always be published in registration or registration update **/
    unsigned                                    publish_value: 2;     /**< 0 for non-publishing,1 if resource value to be published in registration message,
                                                                         2 if resource value to be published in Base64 encoded format */
} sn_nsdl_dynamic_resource_parameters_s;


/**
 * \fn struct nsdl_s *sn_nsdl_init  (uint8_t (*sn_nsdl_tx_cb)(sn_nsdl_capab_e , uint8_t *, uint16_t, sn_nsdl_addr_s *),
 *                          uint8_t (*sn_nsdl_rx_cb)(sn_coap_hdr_s *, sn_nsdl_addr_s *),
 *                          sn_nsdl_mem_s *sn_memory)
 *
 * \brief Initialization function for NSDL library. Initializes NSDL, GRS, HTTP and CoAP.
 *
 * \param *sn_nsdl_tx_callback  A callback function for sending messages.
 *
 * \param *sn_nsdl_rx_callback  A callback function for parsed messages. If received message is not CoAP protocol message (eg. ACK), message for GRS (GET, PUT, POST, DELETE) or
 *                              reply for some DS messages (register message etc.), rx callback will be called.
 *
 * \param *sn_memory            Memory structure which includes function pointers to the allocation and free functions.
 *
 * \return  pointer to created handle structure. NULL if failed
 */
struct nsdl_s *sn_nsdl_init(uint8_t (*sn_nsdl_tx_cb)(struct nsdl_s *, sn_nsdl_capab_e, uint8_t *, uint16_t, sn_nsdl_addr_s *),
                            uint8_t (*sn_nsdl_rx_cb)(struct nsdl_s *, sn_coap_hdr_s *, sn_nsdl_addr_s *),
                            void *(*sn_nsdl_alloc)(uint16_t), void (*sn_nsdl_free)(void *),
                            uint8_t (*sn_nsdl_auto_obs_token_cb)(struct nsdl_s *, const char *, uint8_t *));

/**
 * \fn extern int32_t sn_nsdl_register_endpoint(struct nsdl_s *handle, sn_nsdl_ep_parameters_s *endpoint_info_ptr, const char *uri_query_parameters);
 *
 * \brief Registers endpoint to mbed Device Server.
 * \param *handle               Pointer to nsdl-library handle
 * \param *endpoint_info_ptr    Contains endpoint information.
 * \param *uri_query_parameters Uri query parameters.
 *
 * \return registration message ID, < 0 if failed
 */
extern int32_t sn_nsdl_register_endpoint(struct nsdl_s *handle,
                                         sn_nsdl_ep_parameters_s *endpoint_info_ptr,
                                         const char *uri_query_parameters);

/**
 * \fn extern int32_t sn_nsdl_unregister_endpoint(struct nsdl_s *handle)
 *
 * \brief Sends unregister-message to mbed Device Server.
 *
 * \param *handle               Pointer to nsdl-library handle
 *
 * \return  unregistration message ID, < 0 if failed
 */
extern int32_t sn_nsdl_unregister_endpoint(struct nsdl_s *handle);

/**
 * \fn extern int32_t sn_nsdl_update_registration(struct nsdl_s *handle, uint8_t *lt_ptr, uint8_t lt_len);
 *
 * \brief Update the registration with mbed Device Server.
 *
 * \param *handle   Pointer to nsdl-library handle
 * \param *lt_ptr   Pointer to lifetime value string in ascii form, eg. "1200"
 * \param lt_len    Length of the lifetime string
 *
 * \return  registration update message ID, < 0 if failed
 */
extern int32_t sn_nsdl_update_registration(struct nsdl_s *handle, uint8_t *lt_ptr, uint8_t lt_len);

/**
 * \fn extern int8_t sn_nsdl_set_endpoint_location(struct nsdl_s *handle, uint8_t *location_ptr, uint8_t location_len);
 *
 * \brief Sets the location receievd from Device Server.
 *
 * \param *handle   Pointer to nsdl-library handle
 * \param *lt_ptr   Pointer to location value string , eg. "s322j4k"
 * \param lt_len    Length of the location string
 *
 * \return  success, < 0 if failed
 */
extern int8_t sn_nsdl_set_endpoint_location(struct nsdl_s *handle, uint8_t *location_ptr, uint8_t location_len);

/**
 * \fn extern int8_t sn_nsdl_is_ep_registered(struct nsdl_s *handle)
 *
 * \brief Checks if endpoint is registered.
 *
 * \param *handle   Pointer to nsdl-library handle
 *
 * \return 1 Endpoint registration is done successfully
 * \return 0 Endpoint is not registered
 */
extern int8_t sn_nsdl_is_ep_registered(struct nsdl_s *handle);

/**
 * \fn extern void sn_nsdl_nsp_lost(struct nsdl_s *handle);
 *
 * \brief A function to inform mbed Device C client library if application detects a fault in mbed Device Server registration.
 *
 * \param *handle   Pointer to nsdl-library handle
 *
 * After calling this function sn_nsdl_is_ep_registered() will return "not registered".
 */
extern void sn_nsdl_nsp_lost(struct nsdl_s *handle);

/**
 * \fn extern uint16_t sn_nsdl_send_observation_notification(struct nsdl_s *handle, uint8_t *token_ptr, uint8_t token_len,
 *                                                  uint8_t *payload_ptr, uint16_t payload_len,
 *                                                  sn_coap_observe_e observe,
 *                                                  bool confirmable, sn_coap_content_format_e content_format)
 *
 *
 * \brief Sends observation message to mbed Device Server
 *
 * \param   *handle         Pointer to nsdl-library handle
 * \param   *token_ptr      Pointer to token to be used
 * \param   token_len       Token length
 * \param   *payload_ptr    Pointer to payload to be sent
 * \param   payload_len     Payload length
 * \param   observe         Observe option value to be sent
 * \param   confirmable     Observation message type (confirmable or non-confirmable)
 * \param   content_format  Observation message payload content format
 * \param   message_id      -1 means stored value to be used otherwise new one is generated
 *
 * \return  >0  Success, observation messages message ID
 * \return  <=0   Failure
 */
extern int32_t sn_nsdl_send_observation_notification(struct nsdl_s *handle, uint8_t *token_ptr, uint8_t token_len,
                                                     uint8_t *payload_ptr, uint16_t payload_len,
                                                     sn_coap_observe_e observe,
                                                     bool confirmable,
                                                     sn_coap_content_format_e content_format,
                                                     const int32_t message_id,
                                                     const uint32_t max_age);

/**
 * \fn extern uint32_t sn_nsdl_get_version(void)
 *
 * \brief Version query function.
 *
 * Used to retrieve the version information from the mbed Device C Client library.
 *
 * \return Pointer to library version string
*/
extern char *sn_nsdl_get_version(void);

/**
 * \fn extern int8_t sn_nsdl_process_coap(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *src_ptr)
 *
 * \brief To push CoAP packet to mbed Device C Client library
 *
 * Used to push an CoAP packet to mbed Device C Client library for processing.
 *
 * \param   *handle     Pointer to nsdl-library handle
 *
 * \param   *packet     Pointer to a uint8_t array containing the packet (including the CoAP headers).
 *      After successful execution this array may contain the response packet.
 *
 * \param   *packet_len Pointer to length of the packet. After successful execution this array may contain the length
 *      of the response packet.
 *
 * \param   *src        Pointer to packet source address information. After successful execution this array may contain
 *      the destination address of the response packet.
 *
 * \return  0   Success
 * \return  < 0  Failure
 */
extern int8_t sn_nsdl_process_coap(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *src_ptr);

/**
 * \fn extern int8_t sn_nsdl_exec(struct nsdl_s *handle, uint32_t time);
 *
 * \brief CoAP retransmission function.
 *
 * Used to give execution time for the mbed Device C Client library for retransmissions.
 *
 * \param   *handle Pointer to nsdl-library handle
 *
 * \param  time Time in seconds.
 *
 * \return  0   Success
 * \return  -1  Failure
 */
extern int8_t sn_nsdl_exec(struct nsdl_s *handle, uint32_t time);

/**
 * \fn  extern int8_t sn_nsdl_put_resource(struct nsdl_s *handle, const sn_nsdl_dynamic_resource_parameters_s *res);
 *
 * \brief Resource putting function.
 *
 * Used to put a static or dynamic CoAP resource without creating copy of it.
 * NOTE: Remember that only resource will be owned, not data that it contains
 * NOTE: The resource may be removed from list by sn_nsdl_pop_resource().
 *
 * \param   *res    Pointer to a structure of type sn_nsdl_dynamic_resource_parameters_s that contains the information
 *     about the resource.
 *
 * \return  0   Success
 * \return  -1  Failure
 * \return  -2  Resource already exists
 * \return  -3  Invalid path
 * \return  -4  List adding failure
 */
extern int8_t sn_nsdl_put_resource(struct nsdl_s *handle, sn_nsdl_dynamic_resource_parameters_s *res);

/**
 * \fn  extern int8_t sn_nsdl_pop_resource(struct nsdl_s *handle, const sn_nsdl_dynamic_resource_parameters_s *res);
 *
 * \brief Resource popping function.
 *
 * Used to remove a static or dynamic CoAP resource from lists without deleting it.
 * NOTE: This function is a counterpart of sn_nsdl_put_resource().
 *
 * \param   *res    Pointer to a structure of type sn_nsdl_dynamic_resource_parameters_s that contains the information
 *     about the resource.
 *
 * \return  0   Success
 * \return  -1  Failure
 * \return  -3  Invalid path
 */
extern int8_t sn_nsdl_pop_resource(struct nsdl_s *handle, sn_nsdl_dynamic_resource_parameters_s *res);

/**
 * \fn extern int8_t sn_nsdl_delete_resource(struct nsdl_s *handle, char *path)
 *
 * \brief Resource delete function.
 *
 * Used to delete a resource. If resource has a subresources, these all must also be removed.
 *
 * \param   *handle     Pointer to nsdl-library handle
 * \param   *path_ptr   A pointer to an array containing the path.
 *
 * \return  0   Success
 * \return  -1  Failure (No such resource)
 */
extern int8_t sn_nsdl_delete_resource(struct nsdl_s *handle, const char *path);

/**
 * \fn extern sn_nsdl_dynamic_resource_parameters_s *sn_nsdl_get_resource(struct nsdl_s *handle, char *path)
 *
 * \brief Resource get function.
 *
 * Used to get a resource.
 *
 * \param   *handle     Pointer to nsdl-library handle
  * \param   *path   A pointer to an array containing the path.
 *
 * \return  !NULL   Success, pointer to a sn_nsdl_dynamic_resource_parameters_s that contains the resource information\n
 * \return  NULL    Failure
 */
extern sn_nsdl_dynamic_resource_parameters_s *sn_nsdl_get_resource(struct nsdl_s *handle, const char *path);

/**
 * \fn extern int8_t sn_nsdl_send_coap_message(struct nsdl_s *handle, sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);
 *
 * \brief Send an outgoing CoAP request.
 *
 * \param   *handle Pointer to nsdl-library handle
 * \param   *address_ptr    Pointer to source address struct
 * \param   *coap_hdr_ptr   Pointer to CoAP message to be sent
 *
 * \return  0   Success
 * \return  -1  Failure
 */
extern int8_t sn_nsdl_send_coap_message(struct nsdl_s *handle, sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);

/**
 * \fn extern int32_t sn_nsdl_send_request(struct nsdl_s *handle, sn_coap_msg_code_e msg_code, const char *uri_path, const uint32_t token, const size_t offset, const uint16_t payload_len, const uint8_t* payload_ptr);
 *
 * \brief Send an outgoing CoAP request.
 *
 * \param   *handle       Pointer to nsdl-library handle
 * \param   msg-code      CoAP message code to use for request
 * \param   *uri_path     Path to the data
 * \param   *token        Message token
 * \param   offset        Offset within response body to request
 * \param   payload_len   Message payload length, can be 0 for no payload
 * \param   *payload_ptr  Message payload pointer, can be NULL for no payload
 * \param   type          Type of the download
 *
 * \Return  > 0 Success else Failure
 */
extern int32_t sn_nsdl_send_request(struct nsdl_s *handle,
                                    sn_coap_msg_code_e msg_code,
                                    const char *uri_path,
                                    const uint32_t token,
                                    const size_t offset,
                                    const uint16_t payload_len,
                                    uint8_t *payload_ptr,
                                    DownloadType type);

/**
 * \fn extern int8_t set_NSP_address(struct nsdl_s *handle, uint8_t *NSP_address, uint8_t address_length, uint16_t port, sn_nsdl_addr_type_e address_type);
 *
 * \brief This function is used to set the mbed Device Server address given by an application.
 *
 * \param   *handle Pointer to nsdl-library handle
 * \return  0   Success
 * \return  < 0  Failed to indicate that internal address pointer is not allocated (call nsdl_init() first).
 */
extern int8_t set_NSP_address(struct nsdl_s *handle, uint8_t *NSP_address, uint8_t address_length, uint16_t port, sn_nsdl_addr_type_e address_type);

/**
 * \fn extern int8_t sn_nsdl_destroy(struct nsdl_s *handle);
 *
 * \param   *handle Pointer to nsdl-library handle
 * \brief This function releases all allocated memory in mbed Device C Client library.
 */
extern int8_t sn_nsdl_destroy(struct nsdl_s *handle);

/**
 * \fn extern uint16_t sn_nsdl_oma_bootstrap(struct nsdl_s *handle, sn_nsdl_addr_s *bootstrap_address_ptr, sn_nsdl_ep_parameters_s *endpoint_info_ptr, sn_nsdl_bs_ep_info_t *bootstrap_endpoint_info_ptr);
 *
 * \brief Starts OMA bootstrap process
 *
 * \param   *handle Pointer to nsdl-library handle
 *
 * \return bootstrap message ID, < 0 if failed
 */
extern int32_t sn_nsdl_oma_bootstrap(struct nsdl_s *handle,
                                     sn_nsdl_addr_s *bootstrap_address_ptr,
                                     sn_nsdl_ep_parameters_s *endpoint_info_ptr,
                                     const char *uri_query_parameters);

/**
 * \fn sn_coap_hdr_s *sn_nsdl_build_response(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code)
 *
 * \brief Prepares generic response packet from a request packet. This function allocates memory for the resulting sn_coap_hdr_s
 *
 * \param *handle Pointer to library handle
 * \param *coap_packet_ptr The request packet pointer
 * \param msg_code response messages code
 *
 * \return *coap_packet_ptr The allocated and pre-filled response packet pointer
 *          NULL    Error in parsing the request
 *
 */
extern sn_coap_hdr_s *sn_nsdl_build_response(struct nsdl_s *handle, sn_coap_hdr_s *coap_packet_ptr, uint8_t msg_code);

/**
 * \brief Allocates and initializes options list structure
 *
 * \param *handle Pointer to library handle
 * \param *coap_msg_ptr is pointer to CoAP message that will contain the options
 *
 * If the message already has a pointer to an option structure, that pointer
 * is returned, rather than a new structure being allocated.
 *
 * \return Return value is pointer to the CoAP options structure.\n
 *         In following failure cases NULL is returned:\n
 *          -Failure in given pointer (= NULL)\n
 *          -Failure in memory allocation (malloc() returns NULL)
 */
extern sn_coap_options_list_s *sn_nsdl_alloc_options_list(struct nsdl_s *handle, sn_coap_hdr_s *coap_msg_ptr);

/**
 * \fn void sn_nsdl_release_allocated_coap_msg_mem(struct nsdl_s *handle, sn_coap_hdr_s *freed_coap_msg_ptr)
 *
 * \brief Releases memory of given CoAP message
 *
 *        Note!!! Does not release Payload part
 *
 * \param *handle Pointer to library handle
 *
 * \param *freed_coap_msg_ptr is pointer to released CoAP message
 */
extern void sn_nsdl_release_allocated_coap_msg_mem(struct nsdl_s *handle, sn_coap_hdr_s *freed_coap_msg_ptr);

/**
 * \fn int8_t sn_nsdl_set_retransmission_parameters(struct nsdl_s *handle, uint8_t resending_count, uint8_t resending_intervall)
 *
 * \brief  If re-transmissions are enabled, this function changes resending count and interval.
 *
 * \param *handle Pointer to library handle
 * \param uint8_t resending_count max number of resendings for message
 * \param uint8_t resending_intervall message resending intervall in seconds
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_set_retransmission_parameters(struct nsdl_s *handle, uint8_t resending_count, uint8_t resending_interval);

/**
 * \fn int8_t sn_nsdl_set_retransmission_buffer(struct nsdl_s *handle, uint8_t buffer_size_messages, uint16_t buffer_size_bytes)
 *
 * \brief If re-transmissions are enabled, this function changes message retransmission queue size.
 *  Set size to '0' to disable feature. If both are set to '0', then re-sendings are disabled.
 *
 * \param *handle Pointer to library handle
 * \param uint8_t buffer_size_messages queue size - maximum number of messages to be saved to queue
 * \param uint8_t buffer_size_bytes queue size - maximum size of messages saved to queue
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_set_retransmission_buffer(struct nsdl_s *handle,
                                                uint8_t buffer_size_messages, uint16_t buffer_size_bytes);

/**
 * \fn int8_t sn_nsdl_set_block_size(struct nsdl_s *handle, uint16_t block_size)
 *
 * \brief If block transfer is enabled, this function changes the block size.
 *
 * \param *handle Pointer to library handle
 * \param uint16_t block_size maximum size of CoAP payload. Valid sizes are 16, 32, 64, 128, 256, 512 and 1024 bytes
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_set_block_size(struct nsdl_s *handle, uint16_t block_size);

/**
 * \fn int8_t sn_nsdl_set_duplicate_buffer_size(struct nsdl_s *handle,uint8_t message_count)
 *
 * \brief If dublicate message detection is enabled, this function changes buffer size.
 *
 * \param *handle Pointer to library handle
 * \param uint8_t message_count max number of messages saved for duplicate control
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_set_duplicate_buffer_size(struct nsdl_s *handle, uint8_t message_count);

/**
 * \fn void *sn_nsdl_set_context(const struct nsdl_s *handle, void *context)
 *
 * \brief Set the application defined context parameter for given handle.
 *        This is useful for example when interfacing with c++ objects where a
 *        pointer to object is set as the context, and in the callback functions
 *        the context pointer can be used to call methods for the correct instance
 *        of the c++ object.
 *
 * \param *handle Pointer to library handle
 * \param *context Pointer to the application defined context
 * \return 0 = success, -1 = failure
 */
extern int8_t sn_nsdl_set_context(struct nsdl_s *const handle, void *const context);

/**
 * \fn void *sn_nsdl_get_context(const struct nsdl_s *handle)
 *
 * \brief Get the application defined context parameter for given handle.
 *        This is useful for example when interfacing with c++ objects where a
 *        pointer to object is set as the context, and in the callback functions
 *        the context pointer can be used to call methods for the correct instance
 *        of the c++ object.
 *
 * \param *handle Pointer to library handle
 * \return Pointer to the application defined context
 */
extern void *sn_nsdl_get_context(const struct nsdl_s *const handle);

/**
 * \fn int8_t sn_nsdl_clear_coap_resending_queue(struct nsdl_s *handle)
 *
 * \brief Clean confirmable message list.
 *
 * \param *handle Pointer to library handle
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_clear_coap_resending_queue(struct nsdl_s *handle);

/**
 * \fn int8_t sn_nsdl_clear_coap_sent_blockwise_messages(struct nsdl_s *handle)
 *
 * \brief Clears the sent blockwise messages from the linked list.
 *
 * \param *handle Pointer to library handle
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_clear_coap_sent_blockwise_messages(struct nsdl_s *handle);

/**
 * \fn int8_t sn_nsdl_clear_coap_received_blockwise_messages(struct nsdl_s *handle)
 *
 * \brief Clears the received blockwise messages from the linked list.
 *
 * \param *handle Pointer to library handle
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_clear_coap_received_blockwise_messages(struct nsdl_s *handle);

/**
 * \fn void sn_nsdl_remove_coap_block(struct nsdl_s *handle, sn_nsdl_addr_s *source_address, uint16_t payload_length, void *payload);
 *
 * \brief Remove received blockwise message from the linked list.
 *
 * \param *handle Pointer to library handle
 * \param *source_address Addres from where the block has been received.
 * \param payload_length Length of the removed payload.
 * \param *payload Payload to be removed.
 */
extern void sn_nsdl_remove_coap_block(struct nsdl_s *handle, sn_nsdl_addr_s *source_address, uint16_t payload_length, void *payload);

/**
 * \fn int8_t sn_nsdl_remove_msg_from_retransmission(struct nsdl_s *handle)
 *
 * \brief Clears item from the resend queue.
 *
 * \param *handle Pointer to library handle
 * \param *token Token to be removed
 * \param token_len Length of the token
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_remove_msg_from_retransmission(struct nsdl_s *handle, uint8_t *token, uint8_t token_len);

/**
 * \fn int8_t sn_nsdl_handle_block2_response_internally(struct nsdl_s *handle, uint8_t handle_response)
 *
 * \brief This function change the state whether CoAP library sends the block 2 response automatically or not.
 *
 * \param *handle Pointer to NSDL library handle
 * \param handle_response 1 if CoAP library handles the response sending otherwise 0.
 *
 * \return  0 = success, -1 = failure
 */
extern int8_t sn_nsdl_handle_block2_response_internally(struct nsdl_s *handle, uint8_t handle_response);

#ifdef RESOURCE_ATTRIBUTES_LIST
/**
 * \fn int8_t sn_nsdl_free_resource_attributes_list(struct nsdl_s *handle, sn_nsdl_static_resource_parameters_s *params)
 *
 * \brief Free resource attributes list if free_on_delete is true for params. This will also free all attributes values
 * if they are pointer types.
 *
 * \param *params Pointer to resource static parameters
 */
extern void sn_nsdl_free_resource_attributes_list(sn_nsdl_static_resource_parameters_s *params);

/*
 * \fn bool sn_nsdl_set_resource_attribute(sn_nsdl_static_resource_parameters_s *params, sn_nsdl_attribute_item_s attribute)
 *
 * \brief Set resource link-format attribute value, create if it doesn't exist yet.
 *
 * \param *params Pointer to resource static parameters
 * \param attribute sn_nsdl_attribute_item_s structure containing attribute to set
 * \return True if successful, false on error
 */
extern bool sn_nsdl_set_resource_attribute(sn_nsdl_static_resource_parameters_s *params, const sn_nsdl_attribute_item_s *attribute);

/*
 * \fn bool sn_nsdl_get_resource_attribute(sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute)
 *
 * \brief Get resource link-format attribute value
 *
 * \param *params Pointer to resource static parameters
 * \param attribute sn_nsdl_resource_attribute_t enum value for attribute to get
 * \return Pointer to value or null if attribute did not exist or had no value
 */
extern const char *sn_nsdl_get_resource_attribute(const sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute);

/*
 * \fn bool sn_nsdl_remove_resource_attribute(sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute)
 *
 * \brief Remove resource link-format attribute value
 *
 * \param *params Pointer to resource static parameters
 * \param attribute sn_nsdl_resource_attribute_t enum value for attribute to remove
 */
extern bool sn_nsdl_remove_resource_attribute(sn_nsdl_static_resource_parameters_s *params, sn_nsdl_resource_attribute_t attribute);
#endif

/**
 * \fn bool sn_nsdl_print_coap_data(sn_coap_hdr_s *coap_header_ptr, bool outgoing)
 *
 * \brief Utility function to print all the CoAP header parameters
 *
 * \param *coap_header_ptr CoAP header
 * \param outgoing If True, package is going to be sent to server otherwise receiving
 */
extern void sn_nsdl_print_coap_data(sn_coap_hdr_s *coap_header_ptr, bool outgoing);

/**
 * \fn uint16_t sn_nsdl_get_block_size(struct nsdl_s *handle)
 *
 * \brief Get CoAP block size
 *
 * \param *handle Pointer to library handle
 * \return  block size
 */
extern uint16_t sn_nsdl_get_block_size(const struct nsdl_s *handle);

/**
 * \fn uint8_t sn_nsdl_get_retransmission_count(struct nsdl_s *handle)
 *
 * \brief  Returns retransmission coint
 *
 * \param *handle Pointer to library handle
 * \return  Retransmission count
 */
extern uint8_t sn_nsdl_get_retransmission_count(struct nsdl_s *handle);

/**
 * \fn extern int32_t sn_nsdl_send_coap_ping(struct nsdl_s *handle);
 *
 * \brief Send confirmable CoAP ping message.
 *
 * \param   *handle Pointer to nsdl-library handle
 *
 * \return message ID, < 0 if failed
 */
extern int32_t sn_nsdl_send_coap_ping(struct nsdl_s *handle);

#ifdef __cplusplus
}
#endif

#endif /* SN_NSDL_LIB_H_ */
