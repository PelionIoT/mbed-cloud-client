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

#ifndef MANIFEST_MANAGER_CONFIG_H
#define MANIFEST_MANAGER_CONFIG_H

#include <limits.h>
#include "update-client-common/arm_uc_config.h"

#define MAX_HASH_BYTES 32
#define MAX_SYMM_KEY_BYTES 16
// #define ECC_SIG_BYTES 71
#define MAX_URI_BYTES 128

#define MANIFEST_SUPPORTED_VERSION 1
#define MANIFEST_SUPPORTED_VERSION_EXT 2
#define MANIFEST_MANAGER_NO_STORAGE 1

#ifndef ARM_UC_MM_ENABLE_TEST_VECTORS
#define ARM_UC_MM_ENABLE_TEST_VECTORS 0
#endif

#ifndef ARM_UC_MM_ENABLE_INSERT_TEST_VECTORS
#define ARM_UC_MM_ENABLE_INSERT_TEST_VECTORS 0
#endif

#define RFC_4122_BYTES (128/CHAR_BIT)
#define RFC_4122_WORDS (RFC_4122_BYTES/sizeof(uint32_t))

#define CERT_MAX_STORAGE 1024
#define CA_PREFIX       "com.arm.mbed.update.mm.ca"
#define MANIFEST_PREFIX "com.arm.mbed.update.mm.m"

#define MANIFEST_ROLLBACK_PROTECTION 0

#define CFSTORE_HASH_ID_SIZE ((((256 + CHAR_BIT - 1) / CHAR_BIT + 2) / 3) * 4 + 1)

#define MANIFEST_STORAGE_RETENTION_LEVEL ARM_RETENTION_NVM
// TODO: Enable ACLs for manifest storage
#define MANIFEST_STORAGE_ACLS_ENABLED 0
// TODO: Enable lazy flush
#define MANIFEST_STORAGE_LAZY_FLUSH_ENABLED 0
// TODO: Enable flush-on-close
#define MANIFEST_STORAGE_FLUSH_ON_CLOSE_ENABLED 0
// TODO: Enable storage-detect
#define MANIFEST_STORAGE_STORAGE_DETECT_ENABLED 0
// TODO: Enable async callbacks for config store
#define MFST_ASYNC_KV_ASYNC 1
#endif // MANIFEST_MANAGER_CONFIG_H
