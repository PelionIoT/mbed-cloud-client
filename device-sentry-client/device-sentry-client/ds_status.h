// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __DS_STATUS_H__
#define __DS_STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
* @file de_status.h
*  \brief Device Sentry (DI) status and error codes.
* This list may grow as needed.
*/

#define DS_STATUS_RANGE_BASE 0x0600
#define DS_STATUS_RANGE_END 0x06ff

typedef enum {
    DS_STATUS_SUCCESS = 0,                    //!< Operation completed successfully.
    DS_STATUS_ERROR = DS_STATUS_RANGE_BASE,   //!< Operation ended with an unspecified error.
    DS_STATUS_INVALID_PARAMETER,              //!< A parameter provided to the function was invalid.
    DS_STATUS_INIT_FAILED,                    //!< Initialization of the Device Sentry module has failed.
    DS_STATUS_INVALID_CONFIG,                 //!< Invalid configuration message was received.
    DS_STATUS_ENCODE_FAILED,                  //!< Does not succeed create response message.
    DS_STATUS_UNSUPPORTED_METRIC,             //!< Does not support current metric id.
    DS_MAX_STATUS = DS_STATUS_RANGE_END
} ds_status_e;

#ifdef __cplusplus
}
#endif

#endif // __DS_STATUS_H__
