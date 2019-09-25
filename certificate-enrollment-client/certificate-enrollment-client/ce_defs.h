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

#ifndef __CE_DEFS_H__
#define __CE_DEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * @file ce_defs.h
    *  \brief Certificate Enrollment (CE) public defines.
    * This file, along with `ce_status.h` (included by this file) contains all the defines exposed for the certificate renewal feature.
    * It is included by `MbedCloudClient.h` so you don't need to include it directly.
    */

#include "ce_status.h"

    /** Enumeration representing the initiator of a certificate renewal operation */
    typedef enum {
        CE_INITIATOR_DEVICE,                //!< Operation initiated by the application.
        CE_INITIATOR_SERVER                 //!< Operation initiated by the certificate enrollment service.
    } ce_initiator_e;

    //!< User callback for the certificate renewal feature. char* guaranteed to be persistent only in context of the callback!
    typedef void(*cert_renewal_cb_f)(const char*, ce_status_e, ce_initiator_e);

#ifdef __cplusplus
}
#endif

#endif  //__CE_DEFS_H__
