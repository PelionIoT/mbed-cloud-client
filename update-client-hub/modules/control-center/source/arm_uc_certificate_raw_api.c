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
// ----------------------------------------------------------------------------

#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_CERT_STORE_RAW) && (ARM_UC_FEATURE_CERT_STORE_RAW == 1)

#include "update-client-control-center/arm_uc_certificate.h"
#include "update-client-common/arm_uc_crypto.h"

static const uint8_t *arm_uc_raw_fingerprint;
static uint16_t arm_uc_raw_fingerprint_size;

static const uint8_t *arm_uc_raw_certificate;
static uint16_t arm_uc_raw_certificate_size;

static arm_uc_error_t arm_uc_raw_cert_fetcher(arm_uc_buffer_t *certificate,
                                              const arm_uc_buffer_t *fingerprint,
                                              const arm_uc_buffer_t *DERCertificateList, // DERCertificateList - not used
                                              void (*callback)(arm_uc_error_t, const arm_uc_buffer_t *, const arm_uc_buffer_t *))
{
    UC_CONT_TRACE("Attempting to load certificate");
    arm_uc_error_t err = {ERR_NONE};

    (void)DERCertificateList;
    if (certificate == NULL ||
            certificate->ptr == NULL ||
            callback == NULL) {
        err.code = ARM_UC_CM_ERR_INVALID_PARAMETER;
        return err;
    }

    // Check the buffer size
    if (certificate->size_max < arm_uc_raw_certificate_size) {
        err.code = ARM_UC_CM_ERR_INVALID_PARAMETER;
    }
    const arm_uc_buffer_t fingerprintLocalBuffer = {
        .size_max = arm_uc_raw_fingerprint_size,
        .size = arm_uc_raw_fingerprint_size,
        .ptr = (uint8_t *)arm_uc_raw_fingerprint
    };
    if (err.code == ERR_NONE) {
        // Compare the buffers
        uint32_t rc = ARM_UC_BinCompareCT(fingerprint, &fingerprintLocalBuffer);
        if (rc) {
            err.code = ARM_UC_CM_ERR_NOT_FOUND;
        } else {
            UC_CONT_TRACE("Certificate lookup fingerprint matched.");
            err.code = ERR_NONE;
            certificate->ptr = (uint8_t *)arm_uc_raw_certificate;
            certificate->size = arm_uc_raw_certificate_size;
        }

        if (callback && (err.code == ERR_NONE)) {
            callback(err, certificate, fingerprint);
        }
    }
    return err;
}

static arm_uc_error_t arm_uc_raw_cert_storer(
    const arm_uc_buffer_t *cert,
    const arm_uc_buffer_t *fingerprint,
    void(*callback)(arm_uc_error_t, const arm_uc_buffer_t *))
{
    arm_uc_error_t err = {ERR_NONE};

    if (cert == NULL ||
            fingerprint == NULL ||
            callback == NULL) {
        err.code = ARM_UC_CM_ERR_INVALID_PARAMETER;
        return err;
    }

    if (fingerprint->ptr == NULL || fingerprint->size < (256 / 8) ||
            cert->ptr == NULL || cert->size < (256 / 8)) {
        err.code = ARM_UC_CM_ERR_INVALID_PARAMETER;
    }

    if (err.code == ERR_NONE) {
        arm_uc_raw_fingerprint = fingerprint->ptr;
        arm_uc_raw_fingerprint_size = fingerprint->size;
        arm_uc_raw_certificate = cert->ptr;
        arm_uc_raw_certificate_size = cert->size;
    }

    if (callback && (err.code == ERR_NONE)) {
        callback(err, fingerprint);
    }

    return err;
}

const struct arm_uc_certificate_api arm_uc_certificate_raw_api = {
    .fetch = arm_uc_raw_cert_fetcher,
    .store = arm_uc_raw_cert_storer
};

#endif /* ARM_UC_FEATURE_CERT_STORE_RAW */
