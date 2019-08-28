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
#include "bignum.h"
#include "ecdsa.h"
#include "ecp.h"

#ifdef USE_CN_CBOR

bool GetECKeyFromCoseKeyObj(const cn_cbor *coseObj, byte *ecKeyOut, size_t ecKeyBufferSize, size_t *ecKeySizeOut, cose_errback *perr)
{
    byte rgbKey[512 + 1];
    size_t rgbKeyBytes;
    const cn_cbor *p;
    int groupSizeBytes;

    cose_errback error = { 0 };
    if (perr == NULL) perr = &error;

    // Assume success at first
    perr->err = COSE_ERR_NONE;

    CHECK_CONDITION_AND_PRINT_MESSAGE((coseObj != NULL), COSE_ERR_INVALID_PARAMETER, "coseObj is NULL");

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_Curve);
    CHECK_CONDITION_AND_PRINT_MESSAGE((p != NULL), COSE_ERR_INVALID_PARAMETER, "Failed for cn_cbor_mapget_int getting EC Curve");

    switch (p->v.sint) {
        case 1: // P-256
            groupSizeBytes = 256 / 8;
            break;
        default:
            // Unsupported
            mbed_tracef(TRACE_LEVEL_ERROR, "cose", "Unsupported EC group name size (only P-256 is supported)");
            perr->err = COSE_ERR_INVALID_PARAMETER;
            return false; // failure
    }

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_X);
    CHECK_CONDITION_AND_PRINT_MESSAGE(((p != NULL) && (p->type == CN_CBOR_BYTES)), COSE_ERR_INVALID_PARAMETER, "Failed for cn_cbor_mapget_int geting X point");
    CHECK_CONDITION_AND_PRINT_MESSAGE((p->length == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Invalid X point group size");
    memcpy(rgbKey + 1, p->v.str, p->length);

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_Y);
    CHECK_CONDITION_AND_PRINT_MESSAGE(((p != NULL) && (p->type == CN_CBOR_BYTES)), COSE_ERR_INVALID_PARAMETER, "Failed for cn_cbor_mapget_int geting Y point");

    if (p->type == CN_CBOR_BYTES) {
        rgbKey[0] = 0x04; // Uncompressed
        rgbKeyBytes = (groupSizeBytes * 2) + 1;
        CHECK_CONDITION_AND_PRINT_MESSAGE((p->length == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Invalid Y point group size");
        memcpy(rgbKey + p->length + 1, p->v.str, p->length);
    } else if (p->type == CN_CBOR_TRUE) {
        rgbKeyBytes = (groupSizeBytes) + 1;
        rgbKey[0] = 0x02 + (rgbKey[0] & 0x1); // Compressed
    } else if (p->type == CN_CBOR_FALSE) {
        rgbKeyBytes = (groupSizeBytes) + 1;
        rgbKey[0] = 0x04; // Uncompressed
    } else {
        mbed_tracef(TRACE_LEVEL_ERROR, "cose", "Invalid CBOR type");
        perr->err = COSE_ERR_INVALID_PARAMETER;
        return false; // failure
    }

    CHECK_CONDITION_AND_PRINT_MESSAGE((rgbKeyBytes <= ecKeyBufferSize), COSE_ERR_INVALID_PARAMETER, "Provided buffer of insufficient size");

errorReturn:
    if (perr->err != COSE_ERR_NONE) {
        return false; // failure
    }

    // success
    memcpy(ecKeyOut, rgbKey, rgbKeyBytes);
    *ecKeySizeOut = rgbKeyBytes;
    return true;
} 
bool ECDSA_Verify(
    COSE *pSigner,
    int index,
    const byte *pKey,
    size_t keySize,
    int cbitDigest,
    const unsigned char *rgbToSign,
    size_t cbToSign,
    cose_errback *perr)
{
    palStatus_t palStatus;
    unsigned char rgbDigest[PAL_SHA256_SIZE];
    uint32_t rgbDigestSize = sizeof(rgbDigest);
    cn_cbor *signerSig;
    int signerSigLength;

    int mbedtlsStatus;
    mbedtls_mpi r, s;
    mbedtls_ecp_group grp;

    cose_errback error = { 0 };
    if (perr == NULL) perr = &error;

    int groupSizeBytes;

    groupSizeBytes =  EC_GROUP_SIZE(keySize);

    // FIXME: for demo purposes it is assumed that we're getting the key in DER format from the KCM,
    // when we will switch to a "proof of possession" we have to parse a CBOR object to extract the public key material.
    mbedtls_ecp_point ecKey;

    mbedtls_ecp_point_init(&ecKey);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    // Import R and S points as mbedTLS entities
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Assume success at first
    perr->err = COSE_ERR_NONE;

    // Compute digest on the input hash data

    palStatus = pal_sha256(rgbToSign, cbToSign, rgbDigest);
    CHECK_CONDITION_AND_PRINT_MESSAGE((palStatus == PAL_SUCCESS), COSE_ERR_CRYPTO_FAIL, "Failed for pal_sha256 (paStatus = %" PRIu32 ")", palStatus);

    // Fetch the signature to check against and verify it is legit


    signerSig = _COSE_arrayget_int(pSigner, index);
    CHECK_CONDITION_AND_PRINT_MESSAGE((signerSig != NULL), COSE_ERR_INVALID_PARAMETER, "Failed for _COSE_arrayget_int");
    signerSigLength = signerSig->length;
    CHECK_CONDITION_AND_PRINT_MESSAGE(((signerSigLength / 2) == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Signer invalid signature length");


    // Create mbedTLS EC key (reminder: we currently (for demo purposes) treats the key as a byte stream (not as CBOR entity)
    mbedtlsStatus = mbedtls_ecp_point_read_binary(&grp, &ecKey, pKey, keySize);
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for mbedtls_ecp_point_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

    mbedtlsStatus = mbedtls_mpi_read_binary(&r, signerSig->v.bytes, (signerSigLength / 2));
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for bedtls_mpi_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

    mbedtlsStatus = mbedtls_mpi_read_binary(&s, (signerSig->v.bytes + signerSigLength / 2), (signerSigLength / 2));
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for bedtls_mpi_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

    // Hit the actual EC verify
    mbedtlsStatus = mbedtls_ecdsa_verify(&grp, rgbDigest, rgbDigestSize, &ecKey, &r, &s);
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_CRYPTO_FAIL, "Failed for mbedtls_ecdsa_verify (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);


errorReturn:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&ecKey);
    mbedtls_ecp_group_free(&grp);

    if (perr->err != COSE_ERR_NONE) {
        return false;
    }

    return true; // success
}

#else

bool ECDSA_Verify_tiny(
    COSE *pSigner,
    int index,
    const byte *pKey,
    size_t keySize,
    int cbitDigest,
    const unsigned char *rgbToSign,
    size_t cbToSign,
    cose_errback *perr)
{
    palStatus_t palStatus;
    unsigned char rgbDigest[PAL_SHA256_SIZE];
    uint32_t rgbDigestSize = sizeof(rgbDigest);
    CborParser parser;
    CborValue value;
    CborValue signerSig;
    uint8_t *sig_buffer = NULL;
    size_t sig_buffer_size = 0;
    CborError cbor_error = CborNoError;
    int signerSigLength;

    int mbedtlsStatus;
    mbedtls_mpi r, s;
    mbedtls_ecp_group grp;

    cose_errback error = { 0 };
    if (perr == NULL) perr = &error;

    int groupSizeBytes;

    groupSizeBytes = EC_GROUP_SIZE(keySize);

    // FIXME: for demo purposes it is assumed that we're getting the key in DER format from the KCM,
    // when we will switch to a "proof of possession" we have to parse a CBOR object to extract the public key material.
    mbedtls_ecp_point ecKey;

    mbedtls_ecp_point_init(&ecKey);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    // Import R and S points as mbedTLS entities
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Assume success at first
    perr->err = COSE_ERR_NONE;

    // Compute digest on the input hash data

    palStatus = pal_sha256(rgbToSign, cbToSign, rgbDigest);
    CHECK_CONDITION_AND_PRINT_MESSAGE((palStatus == PAL_SUCCESS), COSE_ERR_CRYPTO_FAIL, "Failed for pal_sha256 (paStatus = %" PRIu32 ")", palStatus);

    // Fetch the signature to check against and verify it is legit


    //Retrieve the data from the message
    cbor_error = cbor_parser_init(pSigner->message_cbor.buffer, pSigner->message_cbor.buffer_size, CborIteratorFlag_NegativeInteger, &parser, &value);
    CHECK_CONDITION(cbor_error == CborNoError, cbor_error);

    cbor_error = cbor_get_array_element(&value, index, &signerSig);
    CHECK_CONDITION(cbor_error == CborNoError, cbor_error);
    CHECK_CONDITION(cbor_value_is_byte_string(&signerSig) == true, cbor_error);

    cbor_error = cbor_value_get_byte_string_chunk(&signerSig, &sig_buffer, &signerSigLength, NULL);
    CHECK_CONDITION(cbor_error == CborNoError, cbor_error);
    CHECK_CONDITION_AND_PRINT_MESSAGE(((signerSigLength / 2) == groupSizeBytes), COSE_ERR_INVALID_PARAMETER, "Signer invalid signature length");


    // Create mbedTLS EC key (reminder: we currently (for demo purposes) treats the key as a byte stream (not as CBOR entity)
    mbedtlsStatus = mbedtls_ecp_point_read_binary(&grp, &ecKey, pKey, keySize);
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for mbedtls_ecp_point_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

    mbedtlsStatus = mbedtls_mpi_read_binary(&r, sig_buffer, (signerSigLength / 2));
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for bedtls_mpi_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);


    mbedtlsStatus = mbedtls_mpi_read_binary(&s, (sig_buffer + signerSigLength / 2), (signerSigLength / 2));
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_INTERNAL, "Failed for bedtls_mpi_read_binary (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

    // Hit the actual EC verify
    mbedtlsStatus = mbedtls_ecdsa_verify(&grp, rgbDigest, rgbDigestSize, &ecKey, &r, &s);
    CHECK_CONDITION_AND_PRINT_MESSAGE((mbedtlsStatus == 0), COSE_ERR_CRYPTO_FAIL, "Failed for mbedtls_ecdsa_verify (mbedtlsStatus =  %" PRIi32 ")", mbedtlsStatus);

errorReturn:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&ecKey);
    mbedtls_ecp_group_free(&grp);

    if (perr->err != COSE_ERR_NONE) {
        return false;
    }

    return true; // success
}
#endif

#ifdef USE_CN_CBOR
bool ECDSA_Sign(COSE * pSigner, int index, const cn_cbor * pKey, int cbitDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HMAC_Validate(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CCM_Decrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_GCM_Decrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CBC_MAC_Validate(COSE_MacMessage * pcose, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool ECDH_ComputeSecret(COSE * pRecipient, cn_cbor ** ppKeyPrivate, const cn_cbor * pKeyPublic, byte ** ppbSecret, size_t * pcbSecret, CBOR_CONTEXT_COMMA cose_errback *perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_Extract(COSE * pcose, const byte * pbKey, size_t cbKey, size_t cbitDigest, byte * rgbDigest, size_t * pcbDigest, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_Expand(COSE * pcose, size_t cbitDigest, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_AES_Expand(COSE * pcose, size_t cbitKey, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_KW_Decrypt(COSE_Enveloped * pcose, const byte * pbKeyIn, size_t cbitKey, const byte * pbCipherText, size_t cbCipherText, byte * pbKeyOut, int * pcbKeyOut, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_GCM_Encrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CBC_MAC_Create(COSE_MacMessage * pcose, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HMAC_Create(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_KW_Encrypt(COSE_RecipientInfo * pcose, const byte * pbKeyIn, int cbitKey, const byte *  pbContent, int  cbContent, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CCM_Encrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

void rand_bytes(byte * pb, size_t cb)
{
    assert(true);
}
#endif
