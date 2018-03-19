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

#include "update-client-control-center/arm_uc_certificate.h"
#include "update-client-common/arm_uc_config.h"

#if ARM_UC_USE_KCM
extern const struct arm_uc_certificate_api arm_uc_certificate_kcm_api;
static const struct arm_uc_certificate_api* arm_uc_registered_certificate_api =
    &arm_uc_certificate_kcm_api;
#elif ARM_UC_USE_CFSTORE
extern const struct arm_uc_certificate_api arm_uc_certificate_cfstore_api;
static const struct arm_uc_certificate_api* arm_uc_registered_certificate_api =
    &arm_uc_certificate_cfstore_api;
#else
#error No configuration store set
#endif

/**
 * @brief Add certificate.
 * @details [long description]
 *
 * @param certificate Pointer to certiface being added.
 * @param certificate_size Certificate length.
 * @param fingerprint Pointer to the fingerprint of the certificate being added.
 * @param fingerprint_size Fingerprint length.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_Certificate_Add(const uint8_t* certificate,
                                      uint16_t certificate_size,
                                      const uint8_t* fingerprint,
                                      uint16_t fingerprint_size,
                                      void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*))
{
    //cert Name: base64(fingerprint)
    const arm_uc_buffer_t fingerprintBuffer = {
        .size = fingerprint_size,
        .size_max = fingerprint_size,
        .ptr = (uint8_t *)fingerprint /* Const Cast safe because target is in a const struct */
    };

    const arm_uc_buffer_t certBuffer = {
        .size = certificate_size,
        .size_max = certificate_size,
        .ptr = (uint8_t *)certificate /* Const Cast safe because target is in a const struct */
    };

    const struct arm_uc_certificate_api* api = arm_uc_registered_certificate_api;

    if (api == NULL || api->store == NULL)
    {
        return (arm_uc_error_t){ ARM_UC_CM_ERR_INVALID_PARAMETER};
    }

    arm_uc_error_t err = api->store(&certBuffer, &fingerprintBuffer, callback);

    if (err.error != 0)
    {
        return err;
    }

    return (arm_uc_error_t){ARM_UC_CM_ERR_NONE};
}

arm_uc_error_t ARM_UC_certificateFetch(arm_uc_buffer_t* certificate,
    const arm_uc_buffer_t* fingerprint,
    const arm_uc_buffer_t* DERCertificateList,
    void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*, const arm_uc_buffer_t*))
{
    if (arm_uc_registered_certificate_api == NULL ||
        arm_uc_registered_certificate_api->fetch == NULL)
    {
        return (arm_uc_error_t){ARM_UC_CM_ERR_INVALID_PARAMETER};
    }

    return arm_uc_registered_certificate_api->fetch(certificate, fingerprint, DERCertificateList, callback);
}
