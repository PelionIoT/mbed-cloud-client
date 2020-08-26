// --------------------------------------------------------------------------------
//   Copyright (c) 2015, cose-wg
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
//   * Neither the name of COSE-C nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------------

#include <stdbool.h>
#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto_cose.h"
#include "pal.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

#ifndef USE_CN_CBOR
/*  This function uses tiny cbor functionality */
static bool get_point_buffer(CborValue *map, int point_id, uint8_t *point_buffer, size_t groupSizeBytes, cose_errback *perr)
{
    CborValue map_element;
    CborError cbor_err = CborNoError;
    size_t element_size = 0;

    //Get value according to point id
    cbor_err = cbor_get_map_element_by_int_key(map, point_id, &map_element);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError && map_element.type == CborByteStringType), COSE_ERR_CBOR, "Failed for cbor_get_map_element_by_int_key geting the point");

    //Get and check size of current point data size
    cbor_err = cbor_value_calculate_string_length(&map_element, &element_size);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError && element_size == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Invalid the point group size");

    //Get current point data, check that the size is as expected
    cbor_err = cbor_value_copy_byte_string(&map_element, point_buffer, &element_size, NULL);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError && element_size == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Failed to copy the point buffer");

errorReturn:
    if (perr->err != COSE_ERR_NONE) {
        return false; // failure
    }
    return true;
}
/*  This function uses tiny cbor functionality */
bool GetECKeyFromCoseBuffer(const uint8_t *coseEncBuffer, size_t coseEncBufferSize, byte *ecKeyOut, size_t ecKeyBufferSize, size_t *ecKeySizeOut, cose_errback *perr)
{
    byte rgbKey[512 + 1];
    size_t rgbKeyBytes;
    int groupSizeBytes;
    CborValue value;
    CborValue map_element;
    CborParser parser;
    CborError cbor_err = CborNoError;
    int curve_id = 0;

    cose_errback error = { 0 };
    if (perr == NULL) perr = &error;

    // Assume success at first
    perr->err = COSE_ERR_NONE;

    CHECK_CONDITION_AND_PRINT_MESSAGE((coseEncBuffer != NULL || coseEncBufferSize != 0 ), COSE_ERR_INVALID_PARAMETER, "Cose encoded buffer is invalid");
    CHECK_CONDITION_AND_PRINT_MESSAGE((ecKeyOut != NULL || ecKeyBufferSize != 0), COSE_ERR_INVALID_PARAMETER, "ecKeyOut buffer is invalid");

    //Check and get curve data
    cbor_err = cbor_parser_init(coseEncBuffer, coseEncBufferSize, CborIteratorFlag_NegativeInteger, &parser, &value);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError), COSE_ERR_CBOR, "Failed in cbor_parser_init");


    cbor_err = cbor_get_map_element_by_int_key(&value, COSE_Key_EC_Curve, &map_element);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError), COSE_ERR_CBOR, "Failed in cbor_get_map_element_by_int_key for EC Curve");

    cbor_err = cbor_value_get_int(&map_element, &curve_id);
    CHECK_CONDITION_AND_PRINT_MESSAGE((cbor_err == CborNoError), COSE_ERR_CBOR, "Failed in cbor_value_get_int for EC Curve");


    switch (curve_id) {
    case 1: // P-256
        groupSizeBytes = 256 / 8;
        break;
    default:
        // Unsupported
        mbed_tracef(TRACE_LEVEL_ERROR, "cose", "Unsupported EC group name size (only P-256 is supported)");
        perr->err = COSE_ERR_INVALID_PARAMETER;
        return false; // failure
    }

    //Check and get x and y points
    CHECK_CONDITION_AND_PRINT_MESSAGE((get_point_buffer(&value, COSE_Key_EC_X, rgbKey + 1, groupSizeBytes, perr) == true), COSE_ERR_CBOR, "Failed to get X point data");
    CHECK_CONDITION_AND_PRINT_MESSAGE((get_point_buffer(&value, COSE_Key_EC_Y, rgbKey + groupSizeBytes + 1, groupSizeBytes, perr) == true), COSE_ERR_CBOR, "Failed to get Y point data");

    //Fill compression type and size of the key
    rgbKey[0] = 0x04; // Uncompressed
    rgbKeyBytes = (groupSizeBytes * 2) + 1;
    CHECK_CONDITION_AND_PRINT_MESSAGE((rgbKeyBytes <= ecKeyBufferSize), COSE_ERR_INVALID_PARAMETER, "Provided buffer of insufficient size");

errorReturn:
    if (perr->err != COSE_ERR_NONE) {
        return false; // failure
    }

    //In case of success copy created key to output buffer
    memcpy(ecKeyOut, rgbKey, rgbKeyBytes);
    //Update the size
    *ecKeySizeOut = rgbKeyBytes;

    return true;
}
#endif
