// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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
#include "fota/fota_crypto_asn_extra.h"
#if (MBED_CLOUD_CLIENT_USE_OPENSSL == 0)
#include "mbedtls/asn1.h"
#else
#include <openssl/asn1.h>
#endif
#include <stdint.h>
#include <stddef.h>

#if (MBED_CLOUD_CLIENT_USE_OPENSSL == 1)
#define MBEDTLS_ERR_ASN1_INVALID_LENGTH    -0x0064

int openssl_asn1_get_enumerated_value(const unsigned char **p,
                                      const unsigned char *end,
                                      int *val)
{
    long item_len = 0;
    int tag = 0, xclass = 0;
    int ret;

    // Parse tag and length
    ret = ASN1_get_object(p, &item_len, &tag, &xclass, end - *p);
    if ((ret & 0x80) || tag != V_ASN1_ENUMERATED)
        return -1; // Not an ENUMERATED

    if (item_len == 0 || item_len > (long)sizeof(int) || (**p & 0x80))
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;

    *val = 0;
    for (long i = 0; i < item_len; i++) {
        *val = (*val << 8) | (*p)[i];
    }
    *p += item_len;

    return 0;
}

int openssl_asn1_get_int64(const unsigned char **p,
                           const unsigned char *end,
                           int64_t *val)
{
    long item_len = 0;
    int tag = 0, xclass = 0;
    int ret;

    // Parse tag/length
    ret = ASN1_get_object(p, &item_len, &tag, &xclass, end - *p);
    if ((ret & 0x80) || tag != V_ASN1_INTEGER)
        return -1; // Not an INTEGER

    if (item_len == 0 || item_len > (long)sizeof(int64_t) || (**p & 0x80))
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;

    *val = 0;
    for (long i = 0; i < item_len; i++) {
        *val = (*val << 8) | (*p)[i];
    }
    *p += item_len;

    return 0;
}

#else

int mbedtls_asn1_get_enumerated_value(unsigned char **p,
                                      const unsigned char *end,
                                      int *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_ENUMERATED)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}

int mbedtls_asn1_get_int64(unsigned char **p,
                           const unsigned char *end,
                           int64_t *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int64_t) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}
#endif
