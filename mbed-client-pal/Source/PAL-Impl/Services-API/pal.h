// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifndef _PAL_H
#define _PAL_H

#ifdef __cplusplus
extern "C" {
#endif
//includes for common headers in PAL
#include "PAL-Impl/Services-API/pal_configuration.h"
#include "PAL-Impl/Services-API/pal_macros.h"
#include "PAL-Impl/Services-API/pal_errors.h"
#include "PAL-Impl/Services-API/pal_types.h"

//includes for modules headers.
#include "PAL-Impl/Services-API/pal_drbg.h"
#include "PAL-Impl/Services-API/pal_fileSystem.h"
#include "PAL-Impl/Services-API/pal_rot.h"
#include "PAL-Impl/Services-API/pal_rtos.h"
#include "PAL-Impl/Services-API/pal_network.h"
#include "PAL-Impl/Services-API/pal_time.h"
#include "PAL-Impl/Services-API/pal_TLS.h"
#include "PAL-Impl/Services-API/pal_Crypto.h"
#include "PAL-Impl/Services-API/pal_entropy.h"
#include "PAL-Impl/Services-API/pal_update.h"
#include "PAL-Impl/Services-API/pal_internalFlash.h"
#include "PAL-Impl/Services-API/pal_sst.h"


/*! \file pal.h
*  \brief PAL.
*   This file contains the general API to initiate and destroy the PAL component.
*   This is part of the PAL service API.
*/


//declarations for global init and destroy of PAL

/*! \brief PAL initialization.
*   This function calls each module's initialization function (if one exists)
*   to allocate the required resources and initiate them.
* \return PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_init(void);

/*! \brief PAL destruction.
*   This function calls each module's destroy function (if one exists)
*   to free resources.
*/
int32_t pal_destroy(void);

#ifdef __cplusplus
}
#endif


#endif //_PAL_H
