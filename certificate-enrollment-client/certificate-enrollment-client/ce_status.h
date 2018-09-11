// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#ifndef __CE_STATUS_H__
#define __CE_STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * @file ce_status.h
    *  \brief Certificate Enrollment (CE) status/error codes.
    * This list may grow as needed.
    */

#define CE_STATUS_RANGE_BASE 0x0500
#define CE_STATUS_RANGE_END 0x05ff

// TBD: need to translate KCM to CE errors
typedef enum {
    CE_STATUS_SUCCESS = 0,                    //!< Operation completed successfully.
    CE_STATUS_ERROR = CE_STATUS_RANGE_BASE,   //!< Operation ended with an unspecified error.
    CE_STATUS_INVALID_PARAMETER,              //!< A parameter provided to the function was invalid.
    CE_STATUS_INSUFFICIENT_BUFFER,            //!< The provided buffer size was insufficient for the required output.
    CE_STATUS_OUT_OF_MEMORY,                  //!< An out-of-memory condition occurred.
    CE_STATUS_ITEM_NOT_FOUND,                 //!< The item was not found in the storage.
    CE_STATUS_DEVICE_BUSY,                    //!< Device currently processing too many certificate renewals
    CE_STATUS_BAD_INPUT_FROM_SERVER,          //!< Server sent a TLV that is either unsupported or malformed
    CE_STATUS_EST_ERROR,
    CE_STATUS_STORAGE_ERROR,                  //!< Storage operation ended with error.
    CE_STATUS_RENEWAL_ITEM_VALIDATION_ERROR,  //!< Operation failed to validate renewal items.
    CE_STATUS_BACKUP_ITEM_ERROR,              //!< Operation failed to create/read/validate backup items.
    CE_STATUS_ORIGINAL_ITEM_ERROR,           //!< Operation failed to create/read/validate original items.
    CE_STATUS_RESTORE_BACKUP_ERROR,           //!< Operation failed to restore backup items.
    CE_STATUS_RENEWAL_STATUS_ERROR,           //!< Operation fialed to create/validate/delete renweal status file.
    CE_STATUS_FORBIDDEN_REQUEST,              //!< Server asked for forbidden request (e.g.: the server is not allowed to renew the device's bootstrap certificate)
    CE_STATUS_ITEM_IS_EMPTY,                  //!< Item was found in storage but has zero length
    CE_STATUS_NOT_INITIALIZED,                //!< Called CertificateEnrollmentClient API before module initialization
    CE_MAX_STATUS = CE_STATUS_RANGE_END
} ce_status_e;

#ifdef __cplusplus
}
#endif

#endif  //__CE_STATUS_H__
