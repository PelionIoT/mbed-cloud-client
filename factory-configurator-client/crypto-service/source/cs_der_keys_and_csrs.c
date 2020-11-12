// ----------------------------------------------------------------------------
// Copyright 2016-2020 ARM Ltd.
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

#include "pv_error_handling.h"
#include "cs_der_keys_and_csrs.h"
#include "cs_der_certs.h"
#include "cs_utils.h"
#include "mbedtls/pk.h"
#include "fcc_malloc.h"
#include "key_slot_allocator.h"
#include "storage_kcm.h"
#include "pv_macros.h"

/*! Frees key handle.
*    @param[in] grp                       curve handle
*    @param[in] key_handle                   key handle.
*    @void
*/
static kcm_status_e cs_free_pal_key_handle(palCurveHandle_t *grp, palECKeyHandle_t *key_handle)
{
    //Free curve handler
    (void)pal_ECGroupFree(grp);
    //Free key handler
    (void)pal_ECKeyFree(key_handle);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((*grp != NULLPTR || *key_handle != NULLPTR), KCM_STATUS_ERROR, "Free handle failed ");

    return KCM_STATUS_SUCCESS;
}


/*! Creates and initializes key handle according to passed parameters.
*    @param[in] key_data                 pointer to  key buffer.
*    @param[in] key_data_size            size of key buffer.
*    @param[in] key_type                 pal key type(public or private)
*    @param[in/out] grp                  curve handle
*    @param[in/out] key_handle           key handle.
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/

static kcm_status_e cs_init_and_set_pal_key_handle(const uint8_t *key_data, size_t key_data_size, palKeyToCheck_t key_type, palCurveHandle_t *grp, palECKeyHandle_t *key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_free_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palGroupIndex_t pal_grp_idx;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != PAL_CHECK_PRIVATE_KEY && key_type != PAL_CHECK_PUBLIC_KEY), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");

    //Create new key handler
    pal_status = pal_ECKeyNew(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    if (key_type == PAL_CHECK_PRIVATE_KEY) {
        //Parse der private key
        pal_status = pal_parseECPrivateKeyFromDER(key_data, key_data_size, *key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPrivateKeyFromDER failed ");
    } else {
        //Parse der public key
        pal_status = pal_parseECPublicKeyFromDER(key_data, key_data_size, *key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromDER failed ");
    }

    //retrieve key curve from key handle
    pal_status = pal_ECKeyGetCurve(*key_handle, &pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECKeyGetCurve failed ");

    //Load the key curve
    pal_status = pal_ECGroupInitAndLoad(grp, pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECGroupInitAndLoad failed ");

    return kcm_status;

exit:
    //Free curve handler and key handle
    kcm_free_status = cs_free_pal_key_handle(grp, key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_free_status != KCM_STATUS_SUCCESS), kcm_free_status, "failed in cs_free_pal_key_handle");

    return kcm_status;
}

//For now only EC keys supported!!!
static kcm_status_e der_key_verify(const uint8_t *der_key, size_t der_key_length, palKeyToCheck_t key_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_free_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;
    palCurveHandle_t grp = NULLPTR;
    bool verified = false;


    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");

    //Create new key handler
    kcm_status = cs_init_and_set_pal_key_handle(der_key, der_key_length, key_type, &grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), kcm_status = kcm_status, "cs_init_and_set_pal_key_handle failed ");

    //Perform key verification
    pal_status = pal_ECCheckKey(grp, key_handle, key_type, &verified);
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((FCC_PAL_SUCCESS != pal_status) || (verified != true)), kcm_status = cs_error_handler(pal_status), exit, "pal_ECCheckKey failed ");

exit:
    //Free curve handler and key handle
    kcm_free_status = cs_free_pal_key_handle(&grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_free_status), kcm_free_status, "failed in cs_free_pal_key_handle ");

    return kcm_status;
}


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
static kcm_status_e key_pair_generate(palECKeyHandle_t ec_key_handle, kcm_crypto_key_scheme_e curve_name, cs_key_handle_t key_h)
{
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palGroupIndex_t pal_group_id;
    cs_key_pair_context_s* key_ctx;

    key_ctx = (cs_key_pair_context_s*)key_h;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_ctx");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_ctx->generated_priv_key_handle == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid generated_priv_key_handle");

    // convert curve_name to pal_group_id
    switch (curve_name) {
        case KCM_SCHEME_EC_SECP256R1:
            pal_group_id = PAL_ECP_DP_SECP256R1;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF(true, KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE, "unsupported curve name");
    }

    // Generate keys
    pal_status = pal_ECKeyGenerateKey(pal_group_id, ec_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to generate keys");

    // Save private key to priv_key_handle
    pal_status = pal_writePrivateKeyWithHandle((palKeyHandle_t)key_ctx->generated_priv_key_handle, ec_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to write private key to out buffer");

    if (key_ctx->generated_pub_key_handle != 0) {
        // Save public key to pub_key_handle
        pal_status = pal_writePublicKeyWithHandle((palKeyHandle_t)key_ctx->generated_pub_key_handle, ec_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to write public key to out buffer");
    }

    return KCM_STATUS_SUCCESS;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT


//For now only EC SECP256R keys supported!!!
kcm_status_e cs_pub_key_get_der_to_raw(const uint8_t *der_key, size_t der_key_length, uint8_t *raw_key_data_out, size_t raw_key_data_max_size, size_t *raw_key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    int mbdtls_result = 0;
    palECKeyHandle_t key_handle = NULLPTR;
    mbedtls_pk_context* localECKey;
    mbedtls_ecp_keypair *ecp_key_pair;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length == 0) || (der_key_length > KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_max_size < KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_size_out value");

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    pal_status = pal_parseECPublicKeyFromDER(der_key, der_key_length, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromDER failed");

    localECKey = (mbedtls_pk_context*)key_handle;
    ecp_key_pair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    //Get raw public key data
    mbdtls_result = mbedtls_ecp_point_write_binary(&ecp_key_pair->grp, &ecp_key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, raw_key_data_act_size_out, raw_key_data_out, raw_key_data_max_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "mbedtls_ecp_point_write_binary failed");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((*raw_key_data_act_size_out != KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "Wrong raw_key_data_act_size_out");

exit:
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);
    return kcm_status;
}

//For now only EC SECP256R keys supported!!!
kcm_status_e cs_pub_key_get_raw_to_der(const uint8_t *raw_key, size_t raw_key_length, uint8_t *der_key_data_out, size_t der_key_data_max_size, size_t *der_key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    int mbdtls_result = 0;
    palECKeyHandle_t key_handle = NULLPTR;
    mbedtls_pk_context* localECKey;
    mbedtls_ecp_keypair *ecp_key_pair;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_length != KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_data_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_size_out value");

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    localECKey = (mbedtls_pk_context*)key_handle;

    mbdtls_result = mbedtls_pk_setup(localECKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "mbedtls_pk_setup failed ");

    ecp_key_pair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    mbdtls_result = mbedtls_ecp_group_load(&ecp_key_pair->grp, MBEDTLS_ECP_DP_SECP256R1);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "mbedtls_ecp_group_load failed ");

    //Fill ecp_key_pair with raw public key data
    mbdtls_result = mbedtls_ecp_point_read_binary(&ecp_key_pair->grp, &ecp_key_pair->Q, raw_key, raw_key_length);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "mbedtls_ecp_point_read_binary failed ");

    pal_status = pal_writePublicKeyToDer(key_handle, der_key_data_out, der_key_data_max_size, der_key_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_writePublicKeyToDer failed ");

exit:
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);
    return kcm_status;
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

//For now only EC SECP256R keys supported!!!
kcm_status_e cs_priv_key_get_der_to_raw(const uint8_t *der_key, size_t der_key_length, uint8_t *raw_key_data_out, size_t raw_key_data_max_size, size_t *raw_key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    int mbdtls_result = 0;
    palECKeyHandle_t key_handle = NULLPTR;
    mbedtls_pk_context* localECKey;
    mbedtls_ecp_keypair *ecp_key_pair;
    size_t key_data_size;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length == 0) || (der_key_length > KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_max_size < KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_size_out value");

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    pal_status = pal_parseECPrivateKeyFromDER(der_key, der_key_length, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromDER failed ");

    localECKey = (mbedtls_pk_context*)key_handle;
    ecp_key_pair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    // Get raw private key size
    key_data_size = mbedtls_mpi_size(&ecp_key_pair->d);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((key_data_size > KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PRIVKEY, exit, "Wrong key_data_size");

    // Get raw private key data
    mbdtls_result = mbedtls_mpi_write_binary(&ecp_key_pair->d, raw_key_data_out, KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PRIVKEY, exit, "mbedtls_ecp_point_write_binary failed ");

    *raw_key_data_act_size_out = KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE;

exit:
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);
    return kcm_status;
}
#endif // MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

kcm_status_e cs_der_priv_key_verify(const uint8_t *key, size_t key_length)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = der_key_verify(key, key_length, PAL_CHECK_PRIVATE_KEY);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Private key verification failed");

    return kcm_status;
}

kcm_status_e cs_der_public_key_verify(const uint8_t *der_key, size_t der_key_length)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = der_key_verify(der_key, der_key_length, PAL_CHECK_PUBLIC_KEY);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Public key verification failed");

    return kcm_status;
}


kcm_status_e cs_ecdsa_verify(const uint8_t *der_pub_key, size_t der_pub_key_len, const uint8_t *hash_dgst, size_t hash_dgst_len, const uint8_t *sign, size_t  signature_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_free_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;
    palCurveHandle_t grp = NULLPTR;
    bool is_sign_verified = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_pub_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid public key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_pub_key_len <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid public key length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_dgst == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_dgst_len != KCM_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sign == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid signature pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid signature size");

    //Create public key pal handle
    kcm_status = cs_init_and_set_pal_key_handle(der_pub_key, der_pub_key_len, PAL_CHECK_PUBLIC_KEY, &grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), kcm_status = kcm_status, "cs_init_and_set_pal_key_handle failed ");

    //Verify the signature
    pal_status = pal_ECDSAVerify(key_handle, (unsigned char*)hash_dgst, (uint32_t)hash_dgst_len, (unsigned char*)sign, signature_size, &is_sign_verified);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECDSAVerify failed ");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((is_sign_verified != true), kcm_status = KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED, exit, "pal_ECDSAVerify failed to verify signature ");

exit:
    //Free curve handler and key handle
    kcm_free_status = cs_free_pal_key_handle(&grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_free_status != KCM_STATUS_SUCCESS), kcm_free_status, "failed in cs_free_pal_key_handle");

    return kcm_status;

}

kcm_status_e cs_ecdsa_sign(const uint8_t *der_priv_key, size_t der_priv_key_length, const uint8_t *hash_dgst, size_t hash_dgst_len, uint8_t *out_sign, size_t  signature_data_max_size, size_t * signature_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_free_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;
    palCurveHandle_t grp = NULLPTR;
    palMDType_t md_type = PAL_SHA256;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_priv_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_priv_key_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private key length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_dgst == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_dgst_len != KCM_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((out_sign == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out signature pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid signature_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_max_size < KCM_ECDSA_SECP256R1_MAX_SIGNATURE_DER_SIZE_IN_BYTES), KCM_STATUS_INVALID_PARAMETER, "Invalid size of signature buffer");

    //Create new key handler
    kcm_status = cs_init_and_set_pal_key_handle(der_priv_key, der_priv_key_length, PAL_CHECK_PRIVATE_KEY, &grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), kcm_status, "cs_init_and_set_pal_key_handle failed ");

    *signature_data_act_size_out = signature_data_max_size;
    //Sign on hash digest
    pal_status = pal_ECDSASign(grp, md_type, key_handle, (unsigned char*)hash_dgst, (uint32_t)hash_dgst_len, out_sign, signature_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECDSASign failed ");

exit:
    //Free curve handler and key handle
    kcm_free_status = cs_free_pal_key_handle(&grp, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_free_status != KCM_STATUS_SUCCESS), kcm_free_status, "failed in cs_free_pal_key_handle");

    return kcm_status;
}

kcm_status_e cs_verify_key_pair(const uint8_t *priv_key_data, size_t priv_key_data_size, const uint8_t *pub_key_data, size_t pub_key_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t out_sign[KCM_ECDSA_SECP256R1_MAX_SIGNATURE_DER_SIZE_IN_BYTES] = { 0 };
    size_t size_of_sign = sizeof(out_sign);
    size_t act_size_of_sign = 0;
    const uint8_t hash_digest[] =
    { 0x34, 0x70, 0xCD, 0x54, 0x7B, 0x0A, 0x11, 0x5F, 0xE0, 0x5C, 0xEB, 0xBC, 0x07, 0xBA, 0x91, 0x88,
        0x27, 0x20, 0x25, 0x6B, 0xB2, 0x7A, 0x66, 0x89, 0x1A, 0x4B, 0xB7, 0x17, 0x11, 0x04, 0x86, 0x6F };

    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid priv_key_data pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_data_size <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private key length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pub_key_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pub_key_data pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pub_key_data_size <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid pub_key length");

    //Sign on hash using private key
    kcm_status = cs_ecdsa_sign(priv_key_data, priv_key_data_size, hash_digest, sizeof(hash_digest), out_sign, size_of_sign, &act_size_of_sign);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_ecdsa_sign failed");

    //Verify the signature with public key
    kcm_status = cs_ecdsa_verify(pub_key_data, pub_key_data_size, hash_digest, sizeof(hash_digest), (const uint8_t*)out_sign, act_size_of_sign);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_ecdsa_sign failed");

    return kcm_status;
}

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
kcm_status_e cs_key_pair_generate(kcm_crypto_key_scheme_e curve_name, cs_key_handle_t key_h)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t ec_key_handle = NULLPTR;

    // Create new key handler
    pal_status = pal_ECKeyNew(&ec_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    // Call to internal key_pair_generate
    kcm_status = key_pair_generate(ec_key_handle, curve_name, key_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate keys");

exit:
    //Free key handler
    if (ec_key_handle != NULLPTR) {
        pal_ECKeyFree(&ec_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((ec_key_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }

    return kcm_status;
}
#endif

static kcm_status_e csr_generate(palECKeyHandle_t priv_key_handle, const kcm_csr_params_s *csr_params,
                                 uint8_t *csr_buff_out, size_t csr_buff_max_size, size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palx509CSRHandle_t x509CSR_handle = NULLPTR;
    palMDType_t pal_md_type;
    uint32_t pal_key_usage = 0;
    uint32_t pal_ext_key_usage = 0;
    uint32_t eku_all_bits = KCM_CSR_EXT_KU_ANY | KCM_CSR_EXT_KU_SERVER_AUTH | KCM_CSR_EXT_KU_CLIENT_AUTH |
        KCM_CSR_EXT_KU_CODE_SIGNING | KCM_CSR_EXT_KU_EMAIL_PROTECTION | KCM_CSR_EXT_KU_TIME_STAMPING | KCM_CSR_EXT_KU_OCSP_SIGNING;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject pointer in csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out csr buffer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid max csr buffer size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out csr buffer size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->ext_key_usage & (~eku_all_bits)), KCM_STATUS_INVALID_PARAMETER, "Invalid extended key usage options");

    // Initialize x509 CSR handle 
    pal_status = pal_x509CSRInit(&x509CSR_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to initialize x509 CSR handle");

    // Set CSR Subject
    pal_status = pal_x509CSRSetSubject(x509CSR_handle, csr_params->subject);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR Subject");

    // Set MD algorithm to SHA256 for the signature
    switch (csr_params->md_type) {
        case KCM_MD_SHA256:
            pal_md_type = PAL_SHA256;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_GOTO_IF(true, kcm_status = KCM_CRYPTO_STATUS_INVALID_MD_TYPE, exit, "MD type not supported");
    }
    pal_status = pal_x509CSRSetMD(x509CSR_handle, pal_md_type);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set MD algorithm");

    // Set keys into CSR
    pal_status = pal_x509CSRSetKey(x509CSR_handle, priv_key_handle, NULLPTR);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to Set keys into CSR");

    // Set CSR key usage
    if (csr_params->key_usage != KCM_CSR_KU_NONE) {
        if (csr_params->key_usage & KCM_CSR_KU_DIGITAL_SIGNATURE) {
            pal_key_usage |= PAL_X509_KU_DIGITAL_SIGNATURE;
        }
        if (csr_params->key_usage & KCM_CSR_KU_NON_REPUDIATION) {
            pal_key_usage |= PAL_X509_KU_NON_REPUDIATION;
        }
        if (csr_params->key_usage & KCM_CSR_KU_KEY_CERT_SIGN) {
            pal_key_usage |= PAL_X509_KU_KEY_CERT_SIGN;
        }
        if (csr_params->key_usage & KCM_CSR_KU_KEY_AGREEMENT) {
            pal_key_usage |= PAL_X509_KU_KEY_AGREEMENT;
        }
        pal_status = pal_x509CSRSetKeyUsage(x509CSR_handle, pal_key_usage);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR key usage");
    }

    // Set CSR extended key usage
    if (csr_params->ext_key_usage != KCM_CSR_EXT_KU_NONE) {
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_ANY) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_ANY;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_SERVER_AUTH) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_SERVER_AUTH;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_CLIENT_AUTH) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_CLIENT_AUTH;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_CODE_SIGNING) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_CODE_SIGNING;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_EMAIL_PROTECTION) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_EMAIL_PROTECTION;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_TIME_STAMPING) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_TIME_STAMPING;
        }
        if (csr_params->ext_key_usage & KCM_CSR_EXT_KU_OCSP_SIGNING) {
            pal_ext_key_usage |= PAL_X509_EXT_KU_OCSP_SIGNING;
        }
        pal_status = pal_x509CSRSetExtendedKeyUsage(x509CSR_handle, pal_ext_key_usage);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR extended key usage");
    }

    // Write the CSR to out buffer in DER format
    pal_status = pal_x509CSRWriteDER(x509CSR_handle, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to write the CSR to out buffer");

exit:
    //Free CSR handler
    if (x509CSR_handle != NULLPTR) {
        pal_x509CSRFree(&x509CSR_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((x509CSR_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free CSR handle failed ");
    }

    return kcm_status;
}

kcm_status_e cs_csr_generate(const kcm_key_handle_t priv_key_handle, const kcm_csr_params_s *csr_params, uint8_t *csr_buff_out,
                             size_t csr_buff_max_size, size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t pal_ec_key_handle = NULLPTR;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_handle == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private key handle");

    // Create new key handler
    pal_status = pal_ECKeyNew(&pal_ec_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    // Parse private key from DER format
    pal_status = pal_parseECPrivateKeyFromHandle((palKeyHandle_t)priv_key_handle, pal_ec_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to parse private key from DER format");

    // Call to internal csr_generate
    kcm_status = csr_generate(pal_ec_key_handle, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate csr");

exit:
    //Free pal_ec_key_handle
    if (pal_ec_key_handle != NULLPTR) {
        pal_ECKeyFree(&pal_ec_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_ec_key_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }
    return kcm_status;
}


kcm_status_e cs_verify_items_correlation(cs_key_handle_t crypto_handle, const uint8_t *certificate_data, size_t certificate_data_len)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_free_status = KCM_STATUS_SUCCESS;
    cs_key_pair_context_s *key_pair_context = (cs_key_pair_context_s *)crypto_handle;
    palX509Handle_t x509_cert = NULLPTR;

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((crypto_handle == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid crypto_handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid certificate_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_data_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid certificate_data_len");

    //Create certificate handle
    kcm_status = cs_create_handle_from_der_x509_cert(certificate_data, certificate_data_len, &x509_cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), kcm_status, "cs_create_handle_from_der_x509_cert failed");

    //Check certificate and private key correlation
    kcm_status = cs_check_cert_with_priv_handle(x509_cert, key_pair_context->generated_priv_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "cs_check_cert_with_priv_data failed");

exit:
    kcm_free_status = cs_close_handle_x509_cert(&x509_cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_free_status), kcm_free_status, "cs_close_handle_x509_cert failed");

    return kcm_status;
}



static kcm_status_e cs_generate_csr_from_certificate(const uint8_t *certificate,
                                                     size_t certificate_size,
                                                     palECKeyHandle_t pal_ec_key_handle,
                                                     uint8_t *csr_buff_out,
                                                     const size_t csr_buff_max_size,
                                                     size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palx509CSRHandle_t pal_csr_handle = NULLPTR;
    palX509Handle_t pal_crt_handle = NULLPTR;

    // Create CRT handle
    kcm_status = cs_create_handle_from_der_x509_cert(certificate, certificate_size, &pal_crt_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((KCM_STATUS_SUCCESS != kcm_status), (kcm_status = kcm_status), exit, "Failed getting handle from certificate");

    // Create CSR handle
    pal_status = pal_x509CSRInit(&pal_csr_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed intializing X509 CSR object");

    // Set keys into CSR
    pal_status = pal_x509CSRSetKey(pal_csr_handle, pal_ec_key_handle, NULLPTR);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to Set keys into CSR");

    // Create CSR from the given CRT
    pal_status = pal_x509CSRFromCertWriteDER(pal_crt_handle, pal_csr_handle, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed generating CSR from Certificate");

exit:
    //Free x509 CSR handle
    if (pal_csr_handle != NULLPTR) {
        pal_status = pal_x509CSRFree(&pal_csr_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status) && (kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free x509 CSR handle failed");
    }
    //Free x509 CRT handle
    if (pal_crt_handle != NULLPTR) {
        pal_status = pal_x509Free(&pal_crt_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status) && (kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free x509 CRT handle failed");
    }

    return kcm_status;
}

kcm_status_e cs_generate_keys_and_create_csr_from_certificate(const uint8_t *certificate,
                                                              size_t certificate_size,
                                                              cs_key_handle_t key_handle,
                                                              cs_renewal_names_s *renewal_items_names,
                                                              uint8_t *csr_buff_out,
                                                              const size_t csr_buff_max_size,
                                                              size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palECKeyHandle_t pal_ec_key_handle = NULLPTR;

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // Get the key context from the handle
    cs_key_pair_context_s * ec_key_ctx = (cs_key_pair_context_s *)(key_handle);
    uint8_t *cs_pub_key_name = NULL;
    size_t cs_pub_key_name_len = 0;
#endif 

    // Create new key handle
    pal_status = pal_ECKeyNew(&pal_ec_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECKeyNew failed");

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    PV_UNUSED_PARAM(renewal_items_names);

    // Call to internal key_pair_generate
    kcm_status = key_pair_generate(pal_ec_key_handle, KCM_SCHEME_EC_SECP256R1, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((KCM_STATUS_SUCCESS != kcm_status), (kcm_status = kcm_status), exit, "Failed to generate keys");
#else

    if (renewal_items_names->cs_pub_key_name != NULL) {
        cs_pub_key_name =(uint8_t*)renewal_items_names->cs_pub_key_name;
        cs_pub_key_name_len = (size_t)strlen(renewal_items_names->cs_pub_key_name);
    }
    //Generate new keys based on existing keys for certificate enrollment
    kcm_status = storage_ce_generate_keys((const uint8_t*)renewal_items_names->cs_priv_key_name,
        (size_t)strlen(renewal_items_names->cs_priv_key_name),
        (const uint8_t*)cs_pub_key_name,
        cs_pub_key_name_len,
        &ec_key_ctx->generated_priv_key_handle,
        &ec_key_ctx->generated_pub_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((KCM_STATUS_SUCCESS != kcm_status), (kcm_status = kcm_status), exit, "Failed in storage_ce_generate_keys");

    //Get EC handle from generated private key kcm handle
    pal_status = pal_parseECPrivateKeyFromHandle(ec_key_ctx->generated_priv_key_handle, pal_ec_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to parse key handle");
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    //Generate csr from the certificate using generated private EC handle
    kcm_status = cs_generate_csr_from_certificate(certificate, certificate_size, pal_ec_key_handle, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((KCM_STATUS_SUCCESS != kcm_status), (kcm_status = kcm_status), exit, "Failed to generate csr from certificate");

exit:

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // on error, remove keys and set_entry_id to zero
    if (KCM_STATUS_SUCCESS != kcm_status) {
        kcm_status_e kcm_internal_status; //this status is returned in case storage_ce_destroy_ce_key fails, otherwise original error kcm_status is returned 
    
        if (ec_key_ctx->generated_priv_key_handle != 0) {
            kcm_internal_status = storage_ce_destroy_ce_key((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_internal_status), kcm_internal_status, "Failed to remove CE private key");
        }
        if (ec_key_ctx->generated_pub_key_handle != 0) {
            kcm_internal_status = storage_ce_destroy_ce_key((const uint8_t*)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_internal_status), kcm_internal_status, "Failed to remove CE public key");
        }
    }
#endif

    //Free key handle
    if (pal_ec_key_handle != NULLPTR) {
        pal_status = pal_ECKeyFree(&pal_ec_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status) && (kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed");
    }
    return kcm_status;
}

kcm_status_e cs_key_pair_new(cs_key_handle_t *key_h, bool write_public_key)
{

    palStatus_t pal_status;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cs_ec_key_h ");

    cs_key_pair_context_s* key_pair_context = fcc_malloc(sizeof(cs_key_pair_context_s));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_pair_context == NULL), KCM_STATUS_OUT_OF_MEMORY, "Failed to get valid key_pair_context");

    key_pair_context->generated_priv_key_handle = 0;
    key_pair_context->generated_pub_key_handle = 0;

    pal_status = pal_newKeyHandle((palKeyHandle_t*)&(key_pair_context->generated_priv_key_handle), KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), free_and_exit, "Failed to get valid pal_priv_key_handle");

    if (write_public_key == true) {
        pal_status = pal_newKeyHandle((palKeyHandle_t*)&(key_pair_context->generated_pub_key_handle), KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), free_and_exit, "Failed to get valid pal_pub_key_handle");
    }

    *key_h = (cs_key_handle_t)key_pair_context;

    return kcm_status;

free_and_exit:
    kcm_status = cs_key_pair_free((cs_key_handle_t*)&key_pair_context);
    return kcm_status;
}

kcm_status_e cs_key_pair_free(cs_key_handle_t *key_h)
{
    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h == NULL) || (*key_h == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid cs_ec_key_h ");

    cs_key_pair_context_s* key_pair_context = (cs_key_pair_context_s*)*key_h;

    if (key_pair_context->generated_priv_key_handle != 0) {
        pal_freeKeyHandle((palKeyHandle_t*)&(key_pair_context->generated_priv_key_handle));
    }

    if (key_pair_context->generated_pub_key_handle != 0) {
        pal_freeKeyHandle((palKeyHandle_t*)&(key_pair_context->generated_pub_key_handle));
    }

    fcc_free(key_pair_context);
    *key_h = 0;

    return KCM_STATUS_SUCCESS;
}

kcm_status_e cs_asymmetric_sign(kcm_key_handle_t kcm_prv_key_handle, const uint8_t *hash_digest,
                                size_t hash_digest_size, uint8_t *signature_data_out, size_t signature_data_max_size, size_t *signature_data_act_size_out)
{

    palStatus_t pal_status = FCC_PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palECKeyHandle_t pal_ec_prv_key_handle = NULLPTR;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //create pal EC Key handle for private key
    pal_status = pal_ECKeyNew(&pal_ec_prv_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    //parse private key from handle
    pal_status = pal_parseECPrivateKeyFromHandle((palKeyHandle_t)kcm_prv_key_handle, pal_ec_prv_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPrivateKeyFromHandle failed");

    //get output signature
    pal_status = pal_asymmetricSign(pal_ec_prv_key_handle, PAL_SHA256, hash_digest, hash_digest_size, signature_data_out, signature_data_max_size, signature_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_asymmetricSign failed");

exit:

    //Free key handler
    if (pal_ec_prv_key_handle != NULLPTR) {
        pal_status = pal_ECKeyFree(&pal_ec_prv_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;

}


kcm_status_e  cs_asymmetric_verify(kcm_key_handle_t kcm_public_key_handle, const uint8_t *hash_digest,
                                   size_t hash_digest_size, const uint8_t *signature, size_t signature_len)
{

    palStatus_t pal_status = FCC_PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palECKeyHandle_t pal_ec_pub_key_handle = NULLPTR;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //create pal EC Key handle for public key
    pal_status = pal_ECKeyNew(&pal_ec_pub_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    //parse public key from handle
    pal_status = pal_parseECPublicKeyFromHandle((palKeyHandle_t)kcm_public_key_handle, pal_ec_pub_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromHandle failed");

    //verify the signature
    pal_status = pal_asymmetricVerify(pal_ec_pub_key_handle, PAL_SHA256, hash_digest, hash_digest_size, signature, signature_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_asymmetricVerify failed");

exit:

    //Free key handler
    if (pal_ec_pub_key_handle != NULLPTR) {
        pal_status = pal_ECKeyFree(&pal_ec_pub_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;

}


kcm_status_e cs_ecdh_key_agreement(kcm_key_handle_t kcm_private_key_handle, const uint8_t *peer_public_key,
                                   size_t peer_public_pub_key_size, uint8_t *shared_secret, size_t shared_secret_max_size, size_t *shared_secret_act_size_out)
{

    palStatus_t pal_status = FCC_PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palECKeyHandle_t pal_ec_prv_key_handle = NULLPTR;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //create pal EC Key handle for private key
    pal_status = pal_ECKeyNew(&pal_ec_prv_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((FCC_PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    //parse private key from handle
    pal_status = pal_parseECPrivateKeyFromHandle((palKeyHandle_t)kcm_private_key_handle, pal_ec_prv_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECKeyNew failed");

    //calculate shared secret
    pal_status = pal_ECDHKeyAgreement(peer_public_key, peer_public_pub_key_size, pal_ec_prv_key_handle, shared_secret, shared_secret_max_size, shared_secret_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((FCC_PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECDHKeyAgreement failed");

exit:

    //Free key handler
    if (pal_ec_prv_key_handle != NULLPTR) {
        pal_status = pal_ECKeyFree(&pal_ec_prv_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;

}


