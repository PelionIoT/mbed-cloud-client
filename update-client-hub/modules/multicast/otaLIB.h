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

// OTA library user interface header file

#ifndef OTALIB_H_
#define OTALIB_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * \file otaLIB.h
 * \brief OTA Library API. OTA (Over-The-Air programming) library takes care of delivering (in router case) and
 *        receiving (in both router and node cases) firmware.
 *
 *  \section ota-api OTA Library API:
 *  - ota_lib_configure(), A function to configure OTA library.
 *
 *  \section ota-api usage:
 *  1. Configure OTA library by ota_lib_configure()
 *
 */

#define OTA_WHOLE_FW_CHECKSUM_LENGTH 32 // In bytes

#define OTA_SESSION_ID_SIZE 16

#define OTA_FRAGMENT_SIZE           1024

// * * * Fragments request bitmask length * * *
#define OTA_FRAGMENTS_REQ_BITMASK_LENGTH 16 // In bytes (bitmask consist of 128 bits: 16 bytes * 8 bits = 128 bits)

/*!
 * \enum ota_device_type_e
 * \brief Enum for Device types.
 */
typedef enum ota_device_type_e
{
    OTA_DEVICE_TYPE_BORDER_ROUTER = 1,
    OTA_DEVICE_TYPE_NODE = 2,
} ota_device_type_e;

/*!
 * \enum ota_process_state_e
 * \brief Enum for OTA process state.
 */
typedef enum ota_process_state_e
{
    OTA_STATE_IDLE,
    // OTA_START_CMD command is received and firmware fragments are ready to receive
    OTA_STATE_STARTED,

    // OTA_ABORT_CMD command is received, continued with OTA_START_CMD
    OTA_STATE_ABORTED,

    // Device is missing fragments and is requesting those
    OTA_STATE_MISSING_FRAGMENTS_REQUESTING,

    // Checksum calculating over whole received firmware is ongoing
    OTA_STATE_CHECKSUM_CALCULATING,

    // Checksum calculating over whole received firmware is failed
    OTA_STATE_CHECKSUM_FAILED,

    // All firmware fragments are received
    OTA_STATE_PROCESS_COMPLETED,

    // Waiting device's reset by application for taking new downloaded own firmware in use
    OTA_STATE_UPDATE_FW,

    // Manifest received
    OTA_STATE_MANIFEST_RECEIVED,

    // Error state
    OTA_STATE_INVALID
} ota_process_state_e;

/*!
 * \enum ota_error_code_e
 * \brief Enum for ok/error codes.
 */
typedef enum ota_error_code_e
{
    OTA_OK = 0,
    // Error values
    OTA_STORAGE_ERROR = 1,
    OTA_PARAMETER_FAIL = 2,
    OTA_OUT_OF_MEMORY = 3,
    OTA_VERSION_NOT_SUPPORTED = 4,
    OTA_NOT_FOUND = 5
} ota_error_code_e;

/*!
 * \enum ota_address_type_e
 * \brief Enum for address type.
 */
typedef enum ota_address_type_e
{
    OTA_ADDRESS_NOT_VALID = 0,
    OTA_ADDRESS_IPV6 = 1,
    OTA_ADDRESS_IPV4 = 2
} ota_address_type_e;

// * * * Structs * * *

/*!
 * \struct ota_ip_address_t
 * \brief IP address structure.
 */
typedef struct ota_ip_address_t
{
    ota_address_type_e type; // Address type, see ota_address_type_e
    uint8_t address_tbl[16]; // IP address
    uint16_t port;           // UDP port number
} ota_ip_address_t;

/*!
 * \enum ota_resource_types_e
 * \brief OTA resource types
 */
typedef enum ota_resource_types
{
    MULTICAST_STATUS = 0,
    MULTICAST_ERROR,
    MULTICAST_READY,
    MULTICAST_SESSION_ID,
    MULTICAST_NODE_COUNT,
    MULTICAST_ESTIMATED_TOTAL_TIME,
    MULTICAST_ESTIMATED_RESEND_TIME
} ota_resource_types_e;

/*!
 * \struct ota_lib_config_data_t
 * \brief OTA library configuring structure.
 */
typedef struct ota_lib_config_data_t
{
    uint8_t device_type;
    ota_ip_address_t unicast_socket_addr;               // Unicast socket address
    ota_ip_address_t mpl_multicast_socket_addr;         // MPL multicast socket address
    ota_ip_address_t link_local_multicast_socket_addr;  // Link local multicast socket address
} ota_lib_config_data_t;

/*!
 * \struct ota_parameters_t
 * \brief Used for storing OTA parameters over reset.
 */
typedef struct ota_parameters_t
{
    uint8_t ota_session_id[OTA_SESSION_ID_SIZE];// OTA process ID
    uint8_t device_type;                        // Device type
    uint16_t fw_segment_count;                  // Firmware segment count
    uint32_t fw_total_byte_count;               // Firmware total btye count
    uint16_t fw_fragment_count;                 // Firmware fragment count
    uint16_t fw_fragment_byte_count;            // Byte count in one firmware fragment
    uint8_t whole_fw_checksum_tbl[OTA_WHOLE_FW_CHECKSUM_LENGTH]; // Whole firmware image checksum
    uint8_t pull_url_length;                        // Only for router: Url where to pull firmware image length
    uint8_t* pull_url_ptr;                          // Only for router: Url where to pull firmware image
    uint8_t ota_process_count;                  // Tells how many OTA processes are active (only in router, in node always one)
    ota_process_state_e ota_state;              // OTA process state
    uint16_t fragments_bitmask_length;          // Received and stored fragments bitmask length in bytes
    uint8_t *fragments_bitmask_ptr;             // Received and stored fragments bitmask. One bit is for one fragment: If bit is 0, fragment is not received.
                                                // Bit order e.g. for segment 1: (fragment 128) MSB...LSB (fragment 1)
} ota_parameters_t;

/*!
 * \struct ota_config_func_pointers_t
 * \brief OTA function pointer configuring structure.
 * Structure is used for configuring OTA.
 */
typedef struct ota_config_func_pointers_t
{
    void *(*mem_alloc_fptr)(size_t);
    void (*mem_free_fptr)(void*);
    void (*request_timer_fptr)(uint8_t, uint32_t);
    void (*cancel_timer_fptr)(uint8_t);

    ota_error_code_e (*store_new_ota_process_fptr)(uint8_t*);
    ota_error_code_e (*remove_stored_ota_process_fptr)(uint8_t*);

    ota_error_code_e (*store_parameters_fptr)(ota_parameters_t*);
    ota_error_code_e (*read_parameters_fptr)(ota_parameters_t*);

    ota_error_code_e (*start_received_fptr)(ota_parameters_t*);
    void (*process_finished_fptr)(uint8_t *);

    uint32_t (*write_fw_bytes_fptr)(uint8_t*, uint32_t, uint32_t, uint8_t*);
    uint32_t (*read_fw_bytes_fptr)(uint8_t*, uint32_t, uint32_t, uint8_t*);

    void (*send_update_fw_cmd_received_info_fptr)(uint32_t);

    int8_t (*socket_send_fptr)(ota_ip_address_t*, uint16_t, uint8_t*);

    uint16_t (*update_resource_value_fptr)(ota_resource_types_e, uint8_t*, uint16_t);

    ota_error_code_e (*manifest_received_fptr)(uint8_t*, uint32_t);

    void (*firmware_ready_fptr)();

    ota_error_code_e (*get_parent_addr_fptr)(uint8_t*);

} ota_config_func_pointers_t;

// * * * Function prototypes * * *

/**
 * \brief A function for configuring OTA library
 * \param nsdl_handle_ptr NSDL handle for handling resources
 * \param lib_config_data_ptr OTA configuration data
 * \param func_pointers_ptr Function pointers for OTA library:
 *          mem_alloc_fptr() Function pointer for allocating memory
 *            Parameters:
 *              -Allocated byte count
 *            Return value:
*              -Data pointer to allocated memory, NULL in error case
 *          mem_free_fptr() Function pointer for freeing allocated memory
 *            Parameters:
 *              -Data pointer to freed memory
 *          request_timer_fptr() Function pointer for requesting timer event
 *            Parameters:
 *              -Timer ID of requested timer
 *              -Timeout time in milliseconds
 *          cancel_timer_fptr() Function pointer for canceling requested timer event
 *            Parameters:
 *              -Timer ID of cancelled timer
 *          store_new_ota_process_fptr() Function pointer for storing new OTA process to storage
 *            Parameters:
 *              -Added OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 *          read_stored_ota_processes_fptr() Function pointer for reading stored OTA processes from storage
 *            Parameters:
 *              -Stored OTA processes
 *            Return value:
 *              -Ok/error status code of performing function
 *          remove_stored_ota_process_fptr() Function pointer for removing stored OTA process from storage
 *            Parameters:
 *              -Removed OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 *          store_state_fptr() Function pointer for OTA library for storing one OTA process state to storage managed by application
 *            Parameters:
 *              -Stored OTA state
 *            Return value:
 *              -Ok/error status code of performing function
 *          read_state_fptr() Function pointer for OTA library for reading one OTA process state from storage managed by application
 *            Parameters:
 *              -OTA process ID for selecting which OTA process state is read
 *              -Data pointer where OTA process state is read
 *               NOTE: OTA library user (OTA application) will allocate memory for data pointers of ota_download_state_t and
 *                     OTA library will free these data pointers with free function given in configure
 *            Return value:
 *              -Ok/error status code of performing function
 *          store_parameters_fptr() Function pointer for storing OTA parameters to storage
 *            Parameters:
 *              -Stored OTA parameters
 *            Return value:
 *              -Ok/error status code of performing function
 *          read_parameters_fptr() Function pointer for reading one OTA process parameters from storage
 *            Parameters:
 *              -OTA process ID for selecting which OTA process parameters are read
 *              -Data pointer where OTA process parameters are read
 *               NOTE: OTA library user (OTA application) will allocate memory for data pointers of ota_parameters_t and
 *                     OTA library will free these data pointers with free function given in configure
 *            Return value:
 *              -Ok/error status code of performing function
 *          get_fw_storing_capacity_fptr() Function pointer for getting byte count of firmware image storing storage
 *            Return value:
 *              -Byte count of total storage for firmware images
 *          write_fw_bytes_fptr() Function pointer for writing firmware bytes to storage
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data to be written)
 *              -To be written data byte count
 *              -Data pointer to be written data
 *            Return value:
 *              -Written byte count
 *          read_fw_bytes_fptr() Function pointer for reading firmware bytes from storage
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data is to read)
 *              -Data byte count to be read
 *              -Data pointer to data to be read
 *            Return value:
 *              -Read byte count
 *          send_update_fw_cmd_received_info_fptr() Function pointer for telling to application that firmware image can be taken in use
 *                                                  NOTE: OTA user (backend) must remove OTA process from data storage with DELETE command
 *            Parameters:
 *              -OTA process ID
 *              -Delay time in seconds before taking new firmware in use
 *          update_device_registration_fptr() Function pointer for device's registration for getting dynamic resource registered right away
 *                                            NOTE: This function pointer can be set to NULL if not wanted to use
 *          socket_send_fptr() Function pointer for sending data to socket
 *            Parameters:
 *              -Sent destination address
 *              -Sent payload length
 *            Return value:
 *              -Success: 0
 *              -Invalid socket ID: -1
 *              -Socket memory allocation fail: -2
 *              -TCP state not established: -3
 *              -Socket TX process busy: -4
 *              -Packet too short: -6
 *          coap_send_notif_fptr() Function pointer for sending notifications via CoAP
 *            Parameters:
 *              -Sent destination address
 *              -Pointer to token to be used
 *              -Token length
 *              -Pointer to payload to be sent
 *              -Payload length
 *              -Pointer to observe number to be sent
 *              -Observe number len
 *              -Observation message type (confirmable or non-confirmable)
 *            Return value:
 *              -Success, observation messages message ID: !0
 *              -Failure: 0
 * \param max_process_count Maximum amount of concurrent processes allowed, Should be always 1 for node.
 * \return Ok/error status code of performing function, see ota_error_code_e
 */
extern ota_error_code_e ota_lib_configure(ota_lib_config_data_t *lib_config_data_ptr,
                                          ota_config_func_pointers_t *func_pointers_ptr,
                                          uint8_t max_process_count);

/**
 * @brief ota_lib_reset Resets OTA lib and frees allocated resources (if any)
 */
extern void ota_lib_reset();

/**
 * \brief A function which must be called by application for OTA library's expired timers
 * \param timer_id Timer ID
 * \return Ok/error status code of performing function, see ota_error_code_e
 */
void ota_timer_expired(uint8_t timer_id);

/**
 * \brief A function which must be called by application for OTA library's received OTA socket data
 * \param payload_length Received payload length
 * \param payload_ptr Received payload data
 * \param source_addr_ptr Source address of received socket data
 */
void ota_socket_receive_data(uint16_t payload_length,
                             uint8_t *payload_ptr,
                             ota_ip_address_t *source_addr_ptr);

/**
 * \brief A function which set download process to completed.
 * Must be used when START command include url to pull image.
 */
void ota_firmware_pulled();

void ota_delete_session(uint8_t* session);

#ifdef __cplusplus
}
#endif

#endif // OTALIB_H_
