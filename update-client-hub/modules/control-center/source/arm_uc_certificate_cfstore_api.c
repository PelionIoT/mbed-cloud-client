// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
// -----------------------------------------------------------------------------

#include "update-client-control-center/arm_uc_certificate.h"
#include "update-client-common/arm_uc_config.h"

#ifndef ARM_UC_USE_CFSTORE
#define ARM_UC_USE_CFSTORE 0
#endif

#if ARM_UC_USE_CFSTORE

#include <string.h>

static const uint8_t* arm_uc_certificate = NULL;
static uint16_t arm_uc_certificate_size = 0;
static const uint8_t* arm_uc_fingerprint = NULL;
static uint16_t arm_uc_fingerprint_size = 0;

static arm_uc_error_t arm_uc_cfstore_cert_storer(const arm_uc_buffer_t* cert,
                                                 const arm_uc_buffer_t* fingerprint,
                                                 void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*))
{
    if (cert == NULL ||
        cert->ptr == NULL ||
        fingerprint == NULL ||
        fingerprint->ptr == NULL)
    {
        return (arm_uc_error_t){ARM_UC_CM_ERR_INVALID_PARAMETER};
    }
    if (cert->size == 0 || fingerprint->size == 0)
    {
        return (arm_uc_error_t){ARM_UC_CM_ERR_INVALID_PARAMETER};
    }

    arm_uc_error_t err = (arm_uc_error_t){ARM_UC_CM_ERR_NONE};

         arm_uc_certificate = cert->ptr;
    arm_uc_certificate_size = cert->size;
         arm_uc_fingerprint = fingerprint->ptr;
    arm_uc_fingerprint_size = fingerprint->size;

    if (err.code == ARM_UC_CM_ERR_NONE && callback)
    {
        callback(err, fingerprint);
    }

    return err;
}

static arm_uc_error_t arm_uc_cfstore_cert_fetcher(arm_uc_buffer_t* certificate,
    const arm_uc_buffer_t* fingerprint,
    const arm_uc_buffer_t* DERCertificateList,
    void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*, const arm_uc_buffer_t*))
{
    arm_uc_error_t err = {ARM_UC_CM_ERR_INVALID_PARAMETER};

    if (fingerprint->size != arm_uc_fingerprint_size)
    {
        err.code = ARM_UC_CM_ERR_NOT_FOUND;
    }
    else if (fingerprint       != NULL &&
             fingerprint->ptr  != NULL &&
             fingerprint->size == arm_uc_fingerprint_size &&
             certificate       != NULL)
    {
        if (0 == memcmp(fingerprint->ptr, arm_uc_fingerprint, arm_uc_fingerprint_size))
        {
            err.code              = ARM_UC_CM_ERR_NONE;
            certificate->ptr      = (uint8_t*) arm_uc_certificate;
            certificate->size     = arm_uc_certificate_size;
            certificate->size_max = arm_uc_certificate_size;
        }
        else
        {
            err.code = ARM_UC_CM_ERR_NOT_FOUND;
        }
    }

    if (err.error == ERR_NONE && callback)
    {
        callback(err, certificate, fingerprint);
    }

    return err;
}

const struct arm_uc_certificate_api arm_uc_certificate_cfstore_api = {
    .fetch = arm_uc_cfstore_cert_fetcher,
    .store = arm_uc_cfstore_cert_storer,
};

#endif // ARM_UC_USE_KCM
