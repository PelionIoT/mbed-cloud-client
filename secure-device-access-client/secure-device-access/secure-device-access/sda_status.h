// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#ifndef __SDA_STATUS_H__
#define __SDA_STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif
/**
* @file sda_status.h
*  \brief Secure device access status/error codes.
* This list may grow as needed.
*/

#define SDA_STATUS_BASE_ERR           0x0   //0
#define SDA_STATUS_BASE_USER_ERROR    0xfffffff  
#define SDA_STATUS_MAX_ERROR          0x7fffffff

typedef enum {
    SDA_STATUS_SUCCESS = SDA_STATUS_BASE_ERR,                               //!< General success.
    SDA_STATUS_ERROR,                                                       //!< General error.
    SDA_STATUS_INVALID_REQUEST,                                             //!< Error in request message was detected.
    SDA_STATUS_DEVICE_INTERNAL_ERROR,                                       //!< Internal error occurred in the device.
    SDA_STATUS_VERIFICATION_ERROR,                                          //!< Error in request message verification was detected.
    SDA_STATUS_NO_MORE_SCOPES,                                              //!< No more scopes in current scopes list.
    SDA_STATUS_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR,                     //!< Insufficient response buffer size for user buffer.
    SDA_STATUS_NOT_INITIALIZED,                                             //!< SDA module wasn't initialized.
    //user external errors
    SDA_STATUS_OPERATION_EXECUTION_ERROR = SDA_STATUS_BASE_USER_ERROR,      //!< Execution of current device operation failed.
    SDA_STATUS_LAST_ERROR = SDA_STATUS_MAX_ERROR

} sda_status_e;


#ifdef __cplusplus
}
#endif

#endif //__SDA_STATUS_H__
