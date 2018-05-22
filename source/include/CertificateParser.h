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

#ifndef CERTIFICATE_PARSER_H
#define CERTIFICATE_PARSER_H

#include "ns_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
*  \brief A utility function to extract Locality field from the mDS certificate and store it to KCM.
*  \param certificate, The certificate from which the field has to be extracted.
*  \param field, The field to be extracted.
*  \param value [OUT], buffer containing field value. Maximum value can be 64 bytes.
*  \return True if success, False if failure.
*/
bool extract_field_from_certificate(const uint8_t* cer, size_t cer_len, const char *field, char* value);

#ifdef __cplusplus
}
#endif
#endif // CERTIFICATE_PARSER_H
