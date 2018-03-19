// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#include "cs_der_keys.h"
#include "pal.h"
#include "cs_utils.h"
#include "cs_hash.h"
#include "pk.h"

//For now only EC keys supported!!!
static kcm_status_e der_key_verify(const uint8_t *der_key, size_t der_key_length, palKeyToCheck_t key_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;
    palCurveHandle_t grp = NULLPTR;
    palGroupIndex_t pal_grp_idx;
    bool verified = false;


    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    //Parse the key from DER format
    if (key_type == PAL_CHECK_PRIVATE_KEY) {
        pal_status = pal_parseECPrivateKeyFromDER(der_key, der_key_length, key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPrivateKeyFromDER failed ");
    } else {
        pal_status = pal_parseECPublicKeyFromDER(der_key, der_key_length, key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromDER failed ");
    }

    //retrieve key curve from key handle
    pal_status = pal_ECKeyGetCurve(key_handle, &pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECKeyGetCurve failed ");

    //Allocate curve handler
    pal_status = pal_ECGroupInitAndLoad(&grp, pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPrivateKeyFromDER failed ");

    //Perform key verification
    pal_status = pal_ECCheckKey(grp, key_handle, key_type, &verified);
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((PAL_SUCCESS != pal_status) || (verified != true)), kcm_status = cs_error_handler(pal_status), exit, "pal_ECCheckKey failed ");


exit:
    //Free curve handle
    (void)pal_ECGroupFree(&grp);
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((grp != NULLPTR || key_handle != NULLPTR), KCM_STATUS_ERROR, "Free handle failed ");
    }

    return kcm_status;
}
//For now only EC SECP256R keys supported!!!
kcm_status_e cs_get_pub_raw_key_from_der(const uint8_t *der_key, size_t der_key_length, uint8_t *raw_key_data_out, size_t raw_key_data_max_size, size_t *raw_key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    int mbdtls_result = 0;
    palECKeyHandle_t key_handle = NULLPTR;
    mbedtls_pk_context* localECKey;
    mbedtls_ecp_keypair *ecp_key_pair;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length != CS_EC_SECP256R1_PK_DER_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_max_size < CS_EC_SECP256R1_PK_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_size_out value");

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    pal_status = pal_parseECPublicKeyFromDER(der_key, der_key_length, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPublicKeyFromDER failed ");

    localECKey = (mbedtls_pk_context*)key_handle;
    ecp_key_pair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    //Get raw public key data
    mbdtls_result = mbedtls_ecp_point_write_binary(&ecp_key_pair->grp, &ecp_key_pair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, raw_key_data_act_size_out, raw_key_data_out, raw_key_data_max_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((mbdtls_result != 0), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "mbedtls_ecp_point_write_binary failed ");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((raw_key_data_max_size != CS_EC_SECP256R1_PK_RAW_SIZE), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "Wrong raw_key_data_max_size ");

exit:
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);
    return kcm_status;
}


kcm_status_e cs_der_priv_key_verify(const uint8_t *key, size_t key_length)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status =  der_key_verify(key, key_length, PAL_CHECK_PRIVATE_KEY);
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

kcm_status_e cs_ecdsa_sign(const uint8_t *der_priv_key, size_t der_priv_key_length,const uint8_t *hash_dgst,size_t size_of_hash_dgst, uint8_t *out_sign, size_t  signature_data_max_size,size_t * signature_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;
    palCurveHandle_t grp = NULLPTR;
    palGroupIndex_t pal_grp_idx;
    palMDType_t md_type = PAL_SHA256;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_priv_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_priv_key_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private key length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_dgst == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((size_of_hash_dgst != CS_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((out_sign == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out signature pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid signature_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_max_size < CS_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES), KCM_STATUS_INVALID_PARAMETER, "Invalid size of signature buffer");

    

    //Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed ");

    //Parse der private key
    pal_status = pal_parseECPrivateKeyFromDER(der_priv_key, der_priv_key_length, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_parseECPrivateKeyFromDER failed ");

    //retrieve key curve from key handle
    pal_status = pal_ECKeyGetCurve(key_handle, &pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECKeyGetCurve failed ");

    //Load the key curve
    pal_status = pal_ECGroupInitAndLoad(&grp, pal_grp_idx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECGroupInitAndLoad failed ");

    *signature_data_act_size_out = signature_data_max_size;
    //Sign on hash digest
    pal_status = pal_ECDSASign(grp, md_type, key_handle, (unsigned char*)hash_dgst, (uint32_t)size_of_hash_dgst, out_sign, signature_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "pal_ECDSASign failed ");

exit:

    //Free curve handler
    (void)pal_ECGroupFree(&grp);
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((grp != NULLPTR || key_handle != NULLPTR), KCM_STATUS_ERROR, "Free handle failed ");
    }
    return kcm_status;
}
