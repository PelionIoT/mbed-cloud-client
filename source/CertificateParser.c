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

#include <stdint.h>
#include "pal.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

bool extract_field_from_certificate(const uint8_t* cer, size_t cer_len, const char *field, char* value)
{
#if 1 // TODO : Uncomment once PAL has feature to extract "L" from certificate
    tr_debug("extract_field_from_certificate");

    palX509Attr_t attr = PAL_X509_L_ATTR;
    if (strcmp(field,"CN") == 0) {
        attr = PAL_X509_CN_ATTR;
    } else if (strcmp(field,"L") == 0) {
        attr = PAL_X509_L_ATTR;
    } else {
        return false;
    }

    palX509Handle_t cert;
    size_t len;
    palStatus_t ret;
    ret = pal_x509Initiate(&cert);
    if (ret != PAL_SUCCESS) {
        tr_error("extract_field_from_certificate - cert init failed: %d", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    ret = pal_x509CertParse(cert, cer, cer_len);
    if (ret != PAL_SUCCESS) {
        tr_error("extract_field_from_certificate - cert parse failed: %d", (int)ret);
        pal_x509Free(&cert);
        return false;
    }    
    ret = pal_x509CertGetAttribute(cert, attr, value, 64, &len);
    if (ret != PAL_SUCCESS) {
        tr_error("extract_field_from_certificate - cert attr get failed: %d", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    pal_x509Free(&cert);
    return true;
#else
    return false;
#endif
}


