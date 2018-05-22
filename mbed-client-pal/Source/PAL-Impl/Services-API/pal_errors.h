/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/


#ifndef _PAL_ERRORS_H
#define _PAL_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pal_types.h"

/*! \file pal_errors.h
 *  \brief PAL errors.
 *   This file contains PAL errors enumeration. These errors are returned to the service layer.
 */

#define PAL_ERR_MODULE_GENERAL_BASE     ((int32_t)0xFFFFFFF0) // -1 << 0x4
#define PAL_ERR_MODULE_PAL_BASE         ((int32_t)0xFFFFFFC0) // -1 << 0x6
#define PAL_ERR_MODULE_C_BASE           ((int32_t)0xFFFFFF00) // -1 << 0x8,
#define PAL_ERR_MODULE_RTOS_BASE        ((int32_t)0xFFFFF000) // -1 << 0xC,
#define PAL_ERR_MODULE_NET_BASE         ((int32_t)0xFFFF0000) // -1 << 0x10,
#define PAL_ERR_MODULE_TLS_BASE         ((int32_t)0xFFF00000) // -1 << 0x14,
#define PAL_ERR_MODULE_CRYPTO_BASE      ((int32_t)0xFF000000) // -1 << 0x18,
#define PAL_ERR_MODULE_FILESYSTEM_BASE  ((int32_t)0xFC000000)
#define PAL_ERR_MODULE_INTERNAL_FLASH_BASE     ((int32_t)0xFC000500)
#define PAL_ERR_MODULE_UPDATE_BASE      ((int32_t)0xF0000000) // -1 << 0x1C,
#define PAL_ERR_MODULE_BITMASK_BASE      ((int32_t)0xE0000000)


typedef enum {
	//Success Codes are positive
	PAL_SUCCESS = 0,

	//All errors are Negative
	// generic errors
	PAL_ERR_GENERAL_BASE =          PAL_ERR_MODULE_GENERAL_BASE,
	PAL_ERR_GENERIC_FAILURE =       PAL_ERR_GENERAL_BASE,       /*! Generic failure*/ // Try to use a more specific error message whenever possible. */
	PAL_ERR_INVALID_ARGUMENT =      PAL_ERR_GENERAL_BASE + 0x01,   /*! One or more of the function arguments is invalid. */
	PAL_ERR_NO_MEMORY =             PAL_ERR_GENERAL_BASE + 0x02,   /*! Failure due to a failed attempt to allocate memory. */
	PAL_ERR_BUFFER_TOO_SMALL =      PAL_ERR_GENERAL_BASE + 0x03,   /*! The buffer given is too small. */
	PAL_ERR_NOT_SUPPORTED =         PAL_ERR_GENERAL_BASE + 0x04,   /*! The operation is not supported by PAL for the current configuration. */
	PAL_ERR_TIMEOUT_EXPIRED =       PAL_ERR_GENERAL_BASE + 0x05,   /*! The timeout for the operation has expired. */
	PAL_ERR_NOT_INITIALIZED =       PAL_ERR_GENERAL_BASE + 0x06,   /*! Component is not initialized */
	PAL_ERR_NULL_POINTER     =      PAL_ERR_GENERAL_BASE + 0x07,   /*! Received a null pointer when it should be initialized. */
	PAL_ERR_CREATION_FAILED =       PAL_ERR_GENERAL_BASE + 0x08,   /*! Failure in creation of the given type, such as mutex or thread. */
	PAL_ERR_END_OF_FILE =           PAL_ERR_GENERAL_BASE + 0x09,   /*! The reading process finished since end of file reached. */
	PAL_ERR_INVALID_TIME =          PAL_ERR_GENERAL_BASE + 0x0A,  /*! Invalid time value. */
	PAL_ERR_GET_DEV_KEY =           PAL_ERR_GENERAL_BASE + 0x0B,  /*! Failure deriving the key from RoT. */
	PAL_ERR_TIME_TRANSLATE =        PAL_ERR_GENERAL_BASE + 0x0C,  /*! Failure to translate the time from "struct tm" to epoch time. */
	PAL_ERR_SYSCALL_FAILED =		PAL_ERR_GENERAL_BASE + 0x0D,  /*! Failure of calling a system call using system, popen, exec and ect.*/

	// pal errors
	PAL_ERR_NOT_IMPLEMENTED =                               PAL_ERR_MODULE_PAL_BASE, /*! Currently not implemented. */
	// c errors
	// RTOS errors
	PAL_ERR_RTOS_ERROR_BASE =                               PAL_ERR_MODULE_RTOS_BASE,      /*! A generic failure in the RTOS module*/ // Try to use a more specific error message whenever possible. */
	PAL_ERR_RTOS_TRNG_FAILED =                              PAL_ERR_MODULE_RTOS_BASE + 1,  /*! failed to get all the required random data */
	PAL_ERR_RTOS_TRNG_PARTIAL_DATA =                        PAL_ERR_MODULE_RTOS_BASE + 2,  /*! get partial random data, instead of getting the full length */
	PAL_ERR_RTOS_PARAMETER =                                PAL_ERR_RTOS_ERROR_BASE + 0x80,/*! PAL mapping of CMSIS error `osErrorParameter`: A parameter error: A mandatory parameter was missing or specified an incorrect object. */
	PAL_ERR_RTOS_RESOURCE =                                 PAL_ERR_RTOS_ERROR_BASE + 0x81,/*! PAL mapping of CMSIS error `osErrorResource`: Resource not available: The specified resource was not available. */
	PAL_ERR_RTOS_TIMEOUT =                                  PAL_ERR_RTOS_ERROR_BASE + 0xC1,/*! PAL mapping of CMSIS error `osErrorTimeoutResource`: Resource not available within the given time: A specified resource was not available within the timeout period. */
	PAL_ERR_RTOS_ISR =                                      PAL_ERR_RTOS_ERROR_BASE + 0x82,/*! PAL mapping of CMSIS error `osErrorISR`: Not allowed in ISR context: The function cannot be called from interrupt service routines. */
	PAL_ERR_RTOS_ISR_RECURSIVE =                            PAL_ERR_RTOS_ERROR_BASE + 0x83,/*! PAL mapping of CMSIS error `osErrorISRRecursive`: Function called multiple times from ISR with same `object.c` */
	PAL_ERR_RTOS_PRIORITY =                                 PAL_ERR_RTOS_ERROR_BASE + 0x84,/*! PAL mapping of CMSIS error `osErrorPriority`: The system cannot determine the priority or the thread has illegal priority. */
	PAL_ERR_RTOS_NO_MEMORY =                                PAL_ERR_RTOS_ERROR_BASE + 0x85,/*! PAL mapping of CMSIS error `osErrorNoMemory`: The system is out of memory: It was impossible to allocate or reserve memory for the operation. */
	PAL_ERR_RTOS_VALUE =                                    PAL_ERR_RTOS_ERROR_BASE + 0x86,/*! PAL mapping of CMSIS error `osErrorValue`: The value of a parameter is out of range. */
	PAL_ERR_RTOS_TASK =                                     PAL_ERR_RTOS_ERROR_BASE + 0x87,/*! PAL mapping - Cannot kill own task. */
	PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT =             PAL_ERR_RTOS_ERROR_BASE + 0x88,/*! Key received by SOTP is not long enough. */
	PAL_ERR_RTOS_BUFFER_NOT_ALIGNED =                       PAL_ERR_RTOS_ERROR_BASE + 0x89,/*! Buffer not aligned to 32 bits*/
	PAL_ERR_RTOS_RTC_SET_TIME_ERROR =                       PAL_ERR_RTOS_ERROR_BASE + 0x8A,
	PAL_ERR_RTOS_RTC_OPEN_DEVICE_ERROR =                    PAL_ERR_RTOS_ERROR_BASE + 0x8B,
	PAL_ERR_RTOS_RTC_GET_TIME_ERROR =                       PAL_ERR_RTOS_ERROR_BASE + 0x8C,
	PAL_ERR_RTOS_NO_PRIVILEGED =   		                    PAL_ERR_RTOS_ERROR_BASE + 0x8D,/*! Insufficient privilege*/
	PAL_ERR_RTOS_RTC_OPEN_IOCTL_ERROR =                     PAL_ERR_RTOS_ERROR_BASE + 0x8E,
	PAL_ERR_NO_HIGH_RES_TIMER_LEFT =                        PAL_ERR_RTOS_ERROR_BASE + 0x8F,/*! only one high resolution timer at a time is supported by pal  */
    PAL_ERR_RTOS_NOISE_BUFFER_FULL =                        PAL_ERR_RTOS_ERROR_BASE + 0x90,/*! Noise buffer is full. */
    PAL_ERR_RTOS_NOISE_BUFFER_IS_READING =                  PAL_ERR_RTOS_ERROR_BASE + 0x91,/*! Noise buffer is currently being read and writes are not allowed while reading. */
    PAL_ERR_RTOS_NOISE_BUFFER_EMPTY =                       PAL_ERR_RTOS_ERROR_BASE + 0x92,/*! Noise buffer is empty. */
    PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL =                    PAL_ERR_RTOS_ERROR_BASE + 0x93,/*! Noise buffer is not full. */
	PAL_ERR_RTOS_OS =                                       PAL_ERR_RTOS_ERROR_BASE + 0xFF,/*! PAL mapping of CMSIS error `osErrorOS`: An unspecified RTOS error: Run-time error but no other error message fits. */


	// Network errors.
	PAL_ERR_SOCKET_ERROR_BASE =                             PAL_ERR_MODULE_NET_BASE,                /*! Generic socket error. */
	PAL_ERR_SOCKET_GENERIC =                                PAL_ERR_SOCKET_ERROR_BASE,              /*! Generic socket error */
	PAL_ERR_SOCKET_NO_BUFFERS =                             PAL_ERR_SOCKET_ERROR_BASE + 1,          /*! No buffers - PAL mapping of Posix error ENOBUFS. */
	PAL_ERR_SOCKET_HOST_UNREACHABLE =                       PAL_ERR_SOCKET_ERROR_BASE + 2,          /*! Host unreachable (routing error) - PAL mapping of Posix error EHOSTUNREACH. */
	PAL_ERR_SOCKET_IN_PROGRES =                             PAL_ERR_SOCKET_ERROR_BASE + 3,          /*! In progress - PAL mapping of Posix error EINPROGRESS. */
	PAL_ERR_SOCKET_INVALID_VALUE =                          PAL_ERR_SOCKET_ERROR_BASE + 4,          /*! Invalid value - PAL mapping of Posix error EINVAL*/
	PAL_ERR_SOCKET_WOULD_BLOCK =                            PAL_ERR_SOCKET_ERROR_BASE + 5,          /*! Would block - PAL mapping of Posix error EWOULDBLOCK. */
	PAL_ERR_SOCKET_ADDRESS_IN_USE =                         PAL_ERR_SOCKET_ERROR_BASE + 6,          /*! Address in use - PAL mapping of Posix error EADDRINUSE. */
	PAL_ERR_SOCKET_ALREADY_CONNECTED =                      PAL_ERR_SOCKET_ERROR_BASE + 7,          /*! Already connected - PAL mapping of Posix error EALREADY. */
	PAL_ERR_SOCKET_CONNECTION_ABORTED =                     PAL_ERR_SOCKET_ERROR_BASE + 8,          /*! Connection aborted - PAL mapping of Posix error ECONNABORTED. */
	PAL_ERR_SOCKET_CONNECTION_RESET =                       PAL_ERR_SOCKET_ERROR_BASE + 9,          /*! Connection reset - PAL mapping of Posix error ECONNRESET. */
	PAL_ERR_SOCKET_NOT_CONNECTED =                          PAL_ERR_SOCKET_ERROR_BASE + 10,         /*! Not connected - PAL mapping of Posix error ENOTCONN. */
	PAL_ERR_SOCKET_INPUT_OUTPUT_ERROR =                     PAL_ERR_SOCKET_ERROR_BASE + 11,         /*! I/O error - PAL mapping of Posix error EIO. */
	PAL_ERR_SOCKET_CONNECTION_CLOSED =                      PAL_ERR_SOCKET_ERROR_BASE + 12,         /*! Connection closed. */
	PAL_ERR_SOCKET_FAILED_TO_SET_SOCKET_TO_NON_BLOCKING =   PAL_ERR_SOCKET_ERROR_BASE + 13,         /*! Failed to set the socket to non-blocking. */
	PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY =                 PAL_ERR_SOCKET_ERROR_BASE + 14,         /*! Invalid Address family field. */
	PAL_ERR_SOCKET_INVALID_ADDRESS =                        PAL_ERR_SOCKET_ERROR_BASE + 15,         /*! Address given was not valid/found. */
	PAL_ERR_SOCKET_DNS_ERROR =                              PAL_ERR_SOCKET_ERROR_BASE + 16,         /*! DNS lookup error. */
	PAL_ERR_SOCKET_HDCP_ERROR =                             PAL_ERR_SOCKET_ERROR_BASE + 17,         /*! HDCP error. */
	PAL_ERR_SOCKET_AUTH_ERROR =                             PAL_ERR_SOCKET_ERROR_BASE + 18,         /*! Authentication error. */
	PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED =                   PAL_ERR_SOCKET_ERROR_BASE + 19,         /*! Socket option not supported. */
	PAL_ERR_SOCKET_SEND_BUFFER_TOO_BIG =                    PAL_ERR_SOCKET_ERROR_BASE + 20,         /*! Buffer sent too large (over supported MTU). */
	PAL_ERR_SOCKET_ALLOCATION_FAILED =                      PAL_ERR_SOCKET_ERROR_BASE + 21,         /*! Failed to allocate the socket. */
	PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED =                PAL_ERR_SOCKET_ERROR_BASE + 22,         /*! operation not permitted */
	PAL_ERR_SOCKET_MAX_NUMBER_OF_INTERFACES_REACHED =       PAL_ERR_SOCKET_ERROR_BASE + 23,         /*! Failed to register the new interface. */
	PAL_ERR_SOCKET_INTERRUPTED  =                           PAL_ERR_SOCKET_ERROR_BASE + 24,         /*! Function call interrupted. */
	//TLS Errors
	PAL_ERR_TLS_ERROR_BASE =                                PAL_ERR_MODULE_TLS_BASE,
	PAL_ERR_TLS_INIT =                                      PAL_ERR_TLS_ERROR_BASE,
	PAL_ERR_TLS_RESOURCE =                                  PAL_ERR_TLS_ERROR_BASE + 1,
	PAL_ERR_TLS_CONFIG_INIT =                               PAL_ERR_TLS_ERROR_BASE + 2,
	PAL_ERR_TLS_CONTEXT_NOT_INITIALIZED =                   PAL_ERR_TLS_ERROR_BASE + 3,
	PAL_ERR_TLS_INVALID_CIPHER =                            PAL_ERR_TLS_ERROR_BASE + 4,
	PAL_ERR_TLS_WANT_READ =                                 PAL_ERR_TLS_ERROR_BASE + 5,
	PAL_ERR_TLS_WANT_WRITE =                                PAL_ERR_TLS_ERROR_BASE + 6,
	PAL_ERR_TLS_CLIENT_RECONNECT =                          PAL_ERR_TLS_ERROR_BASE + 7,
	PAL_ERR_TLS_BAD_INPUT_DATA =                            PAL_ERR_TLS_ERROR_BASE + 8,
	PAL_ERR_TLS_HELLO_VERIFY_REQUIRED =                     PAL_ERR_TLS_ERROR_BASE + 9,
	PAL_ERR_TLS_FAILED_TO_PARSE_CERT =                      PAL_ERR_TLS_ERROR_BASE + 10,
	PAL_ERR_TLS_FAILED_TO_PARSE_KEY =                       PAL_ERR_TLS_ERROR_BASE + 11,
	PAL_ERR_TLS_FAILED_TO_SET_CERT =                        PAL_ERR_TLS_ERROR_BASE + 12,
	PAL_ERR_TLS_PEER_CLOSE_NOTIFY =                         PAL_ERR_TLS_ERROR_BASE + 13,
	PAL_ERR_TLS_MULTIPLE_HANDSHAKE =                   		PAL_ERR_TLS_ERROR_BASE + 14,
	//update Error
	PAL_ERR_UPDATE_ERROR_BASE =                             PAL_ERR_MODULE_UPDATE_BASE,             /*! Generic error. */
	PAL_ERR_UPDATE_ERROR =                                  PAL_ERR_UPDATE_ERROR_BASE,              /*! Unknown error. */
	PAL_ERR_UPDATE_BUSY =                                   PAL_ERR_UPDATE_ERROR_BASE + 1,          /*! Unknown error. */
	PAL_ERR_UPDATE_TIMEOUT =                                PAL_ERR_UPDATE_ERROR_BASE + 2,          /*! Unknown error. */
	PAL_ERR_UPDATE_OUT_OF_BOUNDS =                          PAL_ERR_UPDATE_ERROR_BASE + 3,          /*! Unknown error. */
	PAL_ERR_UPDATE_PALFROM_API =                            PAL_ERR_UPDATE_ERROR_BASE + 4,          /*! Unknown error. */
	PAL_ERR_UPDATE_PALFROM_IO =                             PAL_ERR_UPDATE_ERROR_BASE + 5,          /*! Unknown error. */
	PAL_ERR_UPDATE_END_OF_IMAGE =                           PAL_ERR_UPDATE_ERROR_BASE + 6,          /*! Unknown error. */
	PAL_ERR_UPDATE_CHUNK_TO_SMALL =                         PAL_ERR_UPDATE_ERROR_BASE + 7,          /*! Unknown error. */
	//Crypto Errors
	PAL_ERR_CRYPTO_ERROR_BASE =                             PAL_ERR_MODULE_CRYPTO_BASE,
	PAL_ERR_AES_INVALID_KEY_LENGTH =                        PAL_ERR_CRYPTO_ERROR_BASE,
	PAL_ERR_CERT_PARSING_FAILED =                           PAL_ERR_CRYPTO_ERROR_BASE + 1,
	PAL_ERR_INVALID_MD_TYPE =                               PAL_ERR_CRYPTO_ERROR_BASE + 2,
	PAL_ERR_MD_BAD_INPUT_DATA =                             PAL_ERR_CRYPTO_ERROR_BASE + 3,
	PAL_ERR_PK_SIG_VERIFY_FAILED =                          PAL_ERR_CRYPTO_ERROR_BASE + 4,
	PAL_ERR_ASN1_UNEXPECTED_TAG =                           PAL_ERR_CRYPTO_ERROR_BASE + 5,
	PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED =                PAL_ERR_CRYPTO_ERROR_BASE + 6,
	PAL_ERR_CTR_DRBG_REQUEST_TOO_BIG =                      PAL_ERR_CRYPTO_ERROR_BASE + 7,
	PAL_ERR_ECP_BAD_INPUT_DATA =                            PAL_ERR_CRYPTO_ERROR_BASE + 8,
	PAL_ERR_MPI_ALLOC_FAILED =                              PAL_ERR_CRYPTO_ERROR_BASE + 9,
	PAL_ERR_ECP_FEATURE_UNAVAILABLE =                       PAL_ERR_CRYPTO_ERROR_BASE + 10,
	PAL_ERR_ECP_BUFFER_TOO_SMALL =                          PAL_ERR_CRYPTO_ERROR_BASE + 11,
	PAL_ERR_MPI_BUFFER_TOO_SMALL =                          PAL_ERR_CRYPTO_ERROR_BASE + 12,
	PAL_ERR_CMAC_GENERIC_FAILURE =                          PAL_ERR_CRYPTO_ERROR_BASE + 13,
	PAL_ERR_NOT_SUPPORTED_ASN_TAG =                         PAL_ERR_CRYPTO_ERROR_BASE + 14,
	PAL_ERR_PRIVATE_KEY_BAD_DATA =                          PAL_ERR_CRYPTO_ERROR_BASE + 15,
	PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED =               PAL_ERR_CRYPTO_ERROR_BASE + 16,
	PAL_ERR_PUBLIC_KEY_BAD_DATA =                           PAL_ERR_CRYPTO_ERROR_BASE + 17,
	PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED =                PAL_ERR_CRYPTO_ERROR_BASE + 18,
	PAL_ERR_NOT_SUPPORTED_CURVE =                           PAL_ERR_CRYPTO_ERROR_BASE + 19,
	PAL_ERR_GROUP_LOAD_FAILED =                             PAL_ERR_CRYPTO_ERROR_BASE + 20,
	PAL_ERR_PARSING_PRIVATE_KEY  =                          PAL_ERR_CRYPTO_ERROR_BASE + 21,
	PAL_ERR_PARSING_PUBLIC_KEY   =                          PAL_ERR_CRYPTO_ERROR_BASE + 22,
	PAL_ERR_KEYPAIR_GEN_FAIL     =                          PAL_ERR_CRYPTO_ERROR_BASE + 23,
	PAL_ERR_X509_UNKNOWN_OID     =                          PAL_ERR_CRYPTO_ERROR_BASE + 24,
	PAL_ERR_X509_INVALID_NAME    =                          PAL_ERR_CRYPTO_ERROR_BASE + 25,
	PAL_ERR_FAILED_TO_SET_KEY_USAGE =                       PAL_ERR_CRYPTO_ERROR_BASE + 26,
	PAL_ERR_INVALID_KEY_USAGE    =                          PAL_ERR_CRYPTO_ERROR_BASE + 27,
	PAL_ERR_SET_EXTENSION_FAILED =                          PAL_ERR_CRYPTO_ERROR_BASE + 28,
	PAL_ERR_CSR_WRITE_DER_FAILED =                          PAL_ERR_CRYPTO_ERROR_BASE + 29,
	PAL_ERR_FAILED_TO_COPY_KEYPAIR =                        PAL_ERR_CRYPTO_ERROR_BASE + 30,
	PAL_ERR_FAILED_TO_COPY_GROUP =                          PAL_ERR_CRYPTO_ERROR_BASE + 31,
	PAL_ERR_FAILED_TO_WRITE_SIGNATURE =                     PAL_ERR_CRYPTO_ERROR_BASE + 32,
	PAL_ERR_FAILED_TO_VERIFY_SIGNATURE =                    PAL_ERR_CRYPTO_ERROR_BASE + 33,
	PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY =                   PAL_ERR_CRYPTO_ERROR_BASE + 34,
	PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY  =                   PAL_ERR_CRYPTO_ERROR_BASE + 35,
	PAL_ERR_FAILED_TO_COMPUTE_SHRED_KEY =                   PAL_ERR_CRYPTO_ERROR_BASE + 36,
	PAL_ERR_INVALID_X509_ATTR =                             PAL_ERR_CRYPTO_ERROR_BASE + 37,
	PAL_ERR_INVALID_CIPHER_ID =                             PAL_ERR_CRYPTO_ERROR_BASE + 38,
	PAL_ERR_CMAC_START_FAILED =                             PAL_ERR_CRYPTO_ERROR_BASE + 39,
	PAL_ERR_CMAC_UPDATE_FAILED =                            PAL_ERR_CRYPTO_ERROR_BASE + 40,
	PAL_ERR_CMAC_FINISH_FAILED =                            PAL_ERR_CRYPTO_ERROR_BASE + 41,
	PAL_ERR_INVALID_IOD =                                   PAL_ERR_CRYPTO_ERROR_BASE + 42,
	PAL_ERR_PK_UNKNOWN_PK_ALG =                             PAL_ERR_CRYPTO_ERROR_BASE + 43,
	PAL_ERR_PK_KEY_INVALID_VERSION =                        PAL_ERR_CRYPTO_ERROR_BASE + 44,
	PAL_ERR_PK_KEY_INVALID_FORMAT =                         PAL_ERR_CRYPTO_ERROR_BASE + 45,
	PAL_ERR_PK_PASSWORD_REQUIRED =                          PAL_ERR_CRYPTO_ERROR_BASE + 46,
	PAL_ERR_PK_INVALID_PUBKEY_AND_ASN1_LEN_MISMATCH =       PAL_ERR_CRYPTO_ERROR_BASE + 47,
	PAL_ERR_ECP_INVALID_KEY =                               PAL_ERR_CRYPTO_ERROR_BASE + 48,
	PAL_ERR_FAILED_SET_TIME_CB =                            PAL_ERR_CRYPTO_ERROR_BASE + 49,
	PAL_ERR_HMAC_GENERIC_FAILURE =                          PAL_ERR_CRYPTO_ERROR_BASE + 50,
	PAL_ERR_X509_CERT_VERIFY_FAILED =                       PAL_ERR_CRYPTO_ERROR_BASE + 51,
    PAL_ERR_FAILED_TO_SET_EXT_KEY_USAGE =                   PAL_ERR_CRYPTO_ERROR_BASE + 52,
	PAL_ERR_X509_BADCERT_EXPIRED =                          PAL_ERR_MODULE_BITMASK_BASE + 0x01, //! Value must not be changed in order to be able to create bit mask
	PAL_ERR_X509_BADCERT_FUTURE =                           PAL_ERR_MODULE_BITMASK_BASE + 0x02, //! Value must not be changed in order to be able to create bit mask
	PAL_ERR_X509_BADCERT_BAD_MD =                           PAL_ERR_MODULE_BITMASK_BASE + 0x04, //! Value must not be changed in order to be able to create bit mask
	PAL_ERR_X509_BADCERT_BAD_PK =                           PAL_ERR_MODULE_BITMASK_BASE + 0x08, //! Value must not be changed in order to be able to create bit mask
	PAL_ERR_X509_BADCERT_NOT_TRUSTED =                      PAL_ERR_MODULE_BITMASK_BASE + 0x10, //! Value must not be changed in order to be able to create bit mask
	PAL_ERR_X509_BADCERT_BAD_KEY =                          PAL_ERR_MODULE_BITMASK_BASE + 0x20, //! Value must not be changed in order to be able to create bit mask

	PAL_ERR_FILESYSTEM_ERROR_BASE = 						PAL_ERR_MODULE_FILESYSTEM_BASE,
	PAL_ERR_FS_OFFSET_ERROR =								PAL_ERR_FILESYSTEM_ERROR_BASE + 1,		//!< Offset given is greater than the EOF.
	PAL_ERR_FS_ACCESS_DENIED =								PAL_ERR_FILESYSTEM_ERROR_BASE + 2,		//!< No permission to execute the command due to Permission, file in use.
	PAL_ERR_FS_NAME_ALREADY_EXIST =							PAL_ERR_FILESYSTEM_ERROR_BASE + 3,		//!< Pathname or filename already exists.
	PAL_ERR_FS_INSUFFICIENT_SPACE =							PAL_ERR_FILESYSTEM_ERROR_BASE + 4,		//!< Insufficient space to execute the command.
	PAL_ERR_FS_INVALID_FILE_NAME =							PAL_ERR_FILESYSTEM_ERROR_BASE + 5,		//!< File name not valid.
	PAL_ERR_FS_BAD_FD =										PAL_ERR_FILESYSTEM_ERROR_BASE + 6,		//!< Bad file descriptor pointer.
	PAL_ERR_FS_INVALID_ARGUMENT =							PAL_ERR_FILESYSTEM_ERROR_BASE + 7,		//!< Invalid argument in calling function.
	PAL_ERR_FS_NO_FILE =									PAL_ERR_FILESYSTEM_ERROR_BASE + 8,		//!< Could not find the file.
	PAL_ERR_FS_NO_PATH =									PAL_ERR_FILESYSTEM_ERROR_BASE + 9,		//!< Could not find the path.
	PAL_ERR_FS_DIR_NOT_EMPTY =								PAL_ERR_FILESYSTEM_ERROR_BASE + 10,		//!< Directory not empty.
	PAL_ERR_FS_INVALID_FS =									PAL_ERR_FILESYSTEM_ERROR_BASE + 11,		//!< Invalid file system mounting or drive.
	PAL_ERR_FS_TOO_MANY_OPEN_FD =							PAL_ERR_FILESYSTEM_ERROR_BASE + 12,		//!< Too many open file descriptors simultaneously.
	PAL_ERR_FS_FILENAME_LENGTH =							PAL_ERR_FILESYSTEM_ERROR_BASE + 13,		//!< File name is too long or invalid.
	PAL_ERR_FS_LENGTH_ERROR =								PAL_ERR_FILESYSTEM_ERROR_BASE + 14,		//!< Given length to read/write is wrong.
	PAL_ERR_FS_BUFFER_ERROR =								PAL_ERR_FILESYSTEM_ERROR_BASE + 15,		//!< Given buffer is not initialized.
	PAL_ERR_FS_ERROR =										PAL_ERR_FILESYSTEM_ERROR_BASE + 16,		//!< Generic file system error.
	PAL_ERR_FS_BUSY =										PAL_ERR_FILESYSTEM_ERROR_BASE + 17,		//!< File/directory is open.
	PAL_ERR_FS_INVALID_OPEN_FLAGS =							PAL_ERR_FILESYSTEM_ERROR_BASE + 18,		//!< File open mode is invalid.
	PAL_ERR_FS_FILE_IS_DIR =								PAL_ERR_FILESYSTEM_ERROR_BASE + 19,		//!< File path given is a directory, not a file.
	PAL_ERR_FS_ERROR_IN_SEARCHING =							PAL_ERR_FILESYSTEM_ERROR_BASE + 20, 	//!< Next file in directory could not be found.
    PAL_ERR_FS_DISK_ERR =                                   PAL_ERR_FILESYSTEM_ERROR_BASE + 21, 	//!< A hard error occurred in the low level disk I/O layer.


	PAL_ERR_INTERNAL_FLASH_ERROR_BASE =						PAL_ERR_MODULE_INTERNAL_FLASH_BASE,
	PAL_ERR_INTERNAL_FLASH_GENERIC_FAILURE =				PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x01,
	PAL_ERR_INTERNAL_FLASH_SECTOR_NOT_ALIGNED =				PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x02,
	PAL_ERR_INTERNAL_FLASH_ADDRESS_NOT_ALIGNED =			PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x03,
	PAL_ERR_INTERNAL_FLASH_CROSSING_SECTORS =	 			PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x04,
	PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED =	 			PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x05,
	PAL_ERR_INTERNAL_FLASH_WRONG_SIZE =	 					PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x06,
	PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED =		PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x07,
	PAL_ERR_INTERNAL_FLASH_INIT_ERROR =                     PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x08,
	PAL_ERR_INTERNAL_FLASH_WRITE_ERROR =                    PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x09,
	PAL_ERR_INTERNAL_FLASH_BUFFER_SIZE_NOT_ALIGNED =        PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x0A,
	PAL_ERR_INTERNAL_FLASH_ERASE_ERROR =                    PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x0B,
    PAL_ERR_INTERNAL_FLASH_NOT_INIT_ERROR =                 PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x0C,
    PAL_ERR_INTERNAL_FLASH_MUTEX_RELEASE_ERROR =            PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x0D,  //!< Mutex release  or/and read/write/erase commands failed
    PAL_ERR_INTERNAL_FLASH_FLASH_ZERO_SIZE     =            PAL_ERR_MODULE_INTERNAL_FLASH_BASE + 0x0E,

} palError_t; /*! errors returned by the pal service API  */


#ifdef __cplusplus
}
#endif
#endif //_PAL_ERRORS
