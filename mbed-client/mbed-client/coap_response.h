/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef COAP_RESPONSE_H
#define COAP_RESPONSE_H

/*! \file coap_response.h
 *  \brief CoAP response code values. 
 */

// Note: Don't put any C++ code into this file as this file is included from C sources.

// These values are COAP response codes. See https://tools.ietf.org/html/rfc7252#section-5.9.1
typedef enum {
    COAP_RESPONSE_CREATED = 65,
    COAP_RESPONSE_DELETED = 66,
    COAP_RESPONSE_VALID = 67,
    COAP_RESPONSE_CHANGED = 68,
    COAP_RESPONSE_CONTENT = 69,
    COAP_RESPONSE_CONTINUE = 95,
    COAP_RESPONSE_BAD_REQUEST = 128,
    COAP_RESPONSE_UNAUTHORIZED = 129,
    COAP_RESPONSE_BAD_OPTION = 130,
    COAP_RESPONSE_FORBIDDEN = 131,
    COAP_RESPONSE_NOT_FOUND = 132,
    COAP_RESPONSE_METHOD_NOT_ALLOWED = 133,
    COAP_RESPONSE_NOT_ACCEPTABLE = 134,
    COAP_RESPONSE_REQUEST_ENTITY_INCOMPLETE = 136,
    COAP_RESPONSE_PRECONDITION_FAILED = 140,
    COAP_RESPONSE_REQUEST_ENTITY_TOO_LARGE = 141,
    COAP_RESPONSE_UNSUPPORTED_CONTENT_FORMAT = 143,
    COAP_RESPONSE_INTERNAL_SERVER_ERROR = 160,
    COAP_RESPONSE_NOT_IMPLEMENTED = 161,
    COAP_RESPONSE_BAD_GATEWAY = 162,
    COAP_RESPONSE_SERVICE_UNAVAILABLE = 163,
    COAP_RESPONSE_GATEWAY_TIMEOUT = 164,
    COAP_RESPONSE_PROXYING_NOT_SUPPORTED = 165
} coap_response_code_e;
#endif
