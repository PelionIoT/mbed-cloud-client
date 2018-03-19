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

#ifndef ARM_UPDATE_ERROR_H
#define ARM_UPDATE_ERROR_H

#include <stdint.h>

// Use two characters to form the 16bit module code
#define TWO_CC(A,B) (((A) & 0xFF) | (((B) & 0xFF) << 8))

#define MANIFEST_MANAGER_PREFIX    TWO_CC('M','M')
#define CERTIFICATE_MANAGER_PREFIX TWO_CC('C','M')
#define SOURCE_MANAGER_PREFIX      TWO_CC('S','M')
#define SOURCE_PREFIX              TWO_CC('S','E')
#define FIRMWARE_MANAGER_PREFIX    TWO_CC('F','M')
#define DER_PARSER_PREFIX          TWO_CC('D','P')
#define MBED_TLS_ERROR_PREFIX      TWO_CC('M','T')
#define UPDATE_CRYPTO_PREFIX       TWO_CC('C','U')
#define DEVICE_IDENTITY_PREFIX     TWO_CC('D','I')
#define HUB_PREFIX                 TWO_CC('H','B')

#define ARM_UC_COMMON_ERR_LIST\
    ENUM_FIXED(ERR_NONE,0)\
    ENUM_AUTO(ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ERR_NOT_READY)\

// Manifest manager
#define ARM_UC_MM_ERR_LIST\
    ENUM_FIXED(MFST_ERR_NONE, MANIFEST_MANAGER_PREFIX << 16)\
    ENUM_AUTO(MFST_ERR_NULL_PTR)\
    ENUM_AUTO(MFST_ERR_PENDING)\
    ENUM_AUTO(MFST_ERR_SIZE)\
    ENUM_AUTO(MFST_ERR_DER_FORMAT)\
    ENUM_AUTO(MFST_ERR_FORMAT)\
    ENUM_AUTO(MFST_ERR_VERSION)\
    ENUM_AUTO(MFST_ERR_ROLLBACK)\
    ENUM_AUTO(MFST_ERR_CRYPTO_MODE)\
    ENUM_AUTO(MFST_ERR_HASH)\
    ENUM_AUTO(MFST_ERR_GUID_VENDOR)\
    ENUM_AUTO(MFST_ERR_GUID_DEVCLASS)\
    ENUM_AUTO(MFST_ERR_GUID_DEVICE)\
    ENUM_AUTO(MFST_ERR_CFG_CREATE_FAILED)\
    ENUM_AUTO(MFST_ERR_KEY_SIZE)\
    ENUM_AUTO(MFST_ERR_CERT_INVALID)\
    ENUM_AUTO(MFST_ERR_CERT_NOT_FOUND)\
    ENUM_AUTO(MFST_ERR_CERT_READ)\
    ENUM_AUTO(MFST_ERR_INVALID_SIGNATURE)\
    ENUM_AUTO(MFST_ERR_INVALID_STATE)\
    ENUM_AUTO(MFST_ERR_BAD_EVENT)\
    ENUM_AUTO(MFST_ERR_EMPTY_FIELD)\
    ENUM_AUTO(MFST_ERR_NO_MANIFEST)\
    ENUM_AUTO(MFST_ERR_SIGNATURE_ALGORITHM)\
    ENUM_AUTO(MFST_ERR_UNSUPPORTED_CONDITION)\
    ENUM_AUTO(MFST_ERR_CTR_IV_SIZE)\
    ENUM_AUTO(MFST_ERR_BAD_KEYTABLE_REF)\
    ENUM_AUTO(MFST_ERR_BAD_KEYTABLE)\

// Certificate Manager
#define ARM_UC_CM_ERR_LIST\
    ENUM_FIXED(ARM_UC_CM_ERR_NONE, CERTIFICATE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_CM_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ARM_UC_CM_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_CM_ERR_INVALID_CERT)\
    ENUM_AUTO(ARM_UC_CM_ERR_BLACKLISTED)\

// DER Parser
#define ARM_UC_DP_ERR_LIST\
    ENUM_FIXED(ARM_UC_DP_ERR_NONE, DER_PARSER_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_DP_ERR_UNKNOWN)\
    ENUM_AUTO(ARM_UC_DP_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_DP_ERR_NO_MORE_ELEMENTS)\

// Source Manager
#define ARM_UC_SM_ERR_LIST\
    ENUM_FIXED(SOMA_ERR_NONE, SOURCE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(SOMA_ERR_NO_ROUTE_TO_SOURCE)\
    ENUM_AUTO(SOMA_ERR_SOURCE_REGISTRY_FULL)\
    ENUM_AUTO(SOMA_ERR_SOURCE_NOT_FOUND)\
    ENUM_AUTO(SOMA_ERR_INVALID_PARAMETER)

// Source
#define ARM_UC_SRC_ERR_LIST\
    ENUM_FIXED(SRCE_ERR_NONE, SOURCE_PREFIX << 16)\
    ENUM_AUTO(SRCE_ERR_UNINITIALIZED)\
    ENUM_AUTO(SRCE_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(SRCE_ERR_FAILED)\
    ENUM_AUTO(SRCE_ERR_BUSY)

// Firmware Manager
#define ARM_UC_FM_ERR_LIST\
    ENUM_FIXED(FIRM_ERR_NONE, FIRMWARE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(FIRM_ERR_WRITE)\
    ENUM_AUTO(FIRM_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(FIRM_ERR_ACTIVATE)\
    ENUM_AUTO(FIRM_ERR_UNINITIALIZED)\
    ENUM_AUTO(FIRM_ERR_INVALID_HASH)

#define ARM_UC_CU_ERR_LIST\
    ENUM_FIXED(ARM_UC_CU_ERR_NONE, UPDATE_CRYPTO_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_CU_ERR_INVALID_PARAMETER)\

#define ARM_UC_DI_ERR_LIST\
    ENUM_FIXED(ARM_UC_DI_ERR_NONE, DEVICE_IDENTITY_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_DI_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ARM_UC_DI_ERR_NOT_READY)\
    ENUM_AUTO(ARM_UC_DI_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_DI_ERR_SIZE)\

#define ARM_UC_HB_ERR_LIST\
    ENUM_FIXED(HUB_ERR_NONE, HUB_PREFIX << 16)\
    ENUM_AUTO(HUB_ERR_ROLLBACK_PROTECTION)\

#define ARM_UC_ERR_LIST\
    ARM_UC_COMMON_ERR_LIST\
    ARM_UC_MM_ERR_LIST\
    ARM_UC_CM_ERR_LIST\
    ARM_UC_DP_ERR_LIST\
    ARM_UC_SM_ERR_LIST\
    ARM_UC_SRC_ERR_LIST\
    ARM_UC_FM_ERR_LIST\
    ARM_UC_CU_ERR_LIST\
    ARM_UC_DI_ERR_LIST\
    ARM_UC_HB_ERR_LIST\

enum arm_uc_error {
    #define ENUM_AUTO(name) name,
    #define ENUM_FIXED(name, val) name = val,
    ARM_UC_ERR_LIST
    #undef ENUM_AUTO
    #undef ENUM_FIXED
};
union arm_uc_error_code {
    int32_t code;
    struct {
        int16_t error;
        union {
            uint16_t module;
            uint8_t  modulecc[2];
        };
    };
};

typedef union arm_uc_error_code arm_uc_error_t;

#ifndef ARM_UC_ERR_TRACE
#define ARM_UC_ERR_TRACE 0
#endif

#if ARM_UC_ERR_TRACE
#define ARM_UC_SET_ERROR(ERR, CODE)
    do {(ERR).code = (CODE);} while (0)
#else
#define ARM_UC_SET_ERROR(ERR, CODE)\
    (ERR).code = (CODE)
#endif

#ifdef __cplusplus
extern "C" {
#endif

const char* ARM_UC_err2Str(arm_uc_error_t err);

#ifdef __cplusplus
}
#endif
#endif // ARM_UPDATE_ERROR_H
