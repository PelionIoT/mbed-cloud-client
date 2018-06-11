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
#include "cs_der_keys_and_csrs.h"
#include "pal.h"
#include "cs_utils.h"
#include "cs_hash.h"
#include "pk.h"
#include "kcm_internal.h"

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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((der_key_length != KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid der_key_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((raw_key_data_max_size < KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid raw_key_size_out value");

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
    SA_PV_ERR_RECOVERABLE_GOTO_IF((raw_key_data_max_size != KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE), kcm_status = KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, exit, "Wrong raw_key_data_max_size ");

exit:
    //Free key handler
    (void)pal_ECKeyFree(&key_handle);
    return kcm_status;
}


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

kcm_status_e cs_ecdsa_sign(const uint8_t *der_priv_key, size_t der_priv_key_length, const uint8_t *hash_dgst, size_t size_of_hash_dgst, uint8_t *out_sign, size_t  signature_data_max_size, size_t * signature_data_act_size_out)
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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_max_size < KCM_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES), KCM_STATUS_INVALID_PARAMETER, "Invalid size of signature buffer");


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

static kcm_status_e cs_key_pair_generate_int(palECKeyHandle_t key_handle, kcm_crypto_key_scheme_e curve_name, uint8_t *priv_key_out, size_t priv_key_max_size,
                                             size_t *priv_key_act_size_out, uint8_t *pub_key_out, size_t pub_key_max_size, size_t *pub_key_act_size_out)
{
    palStatus_t pal_status = PAL_SUCCESS;
    palGroupIndex_t pal_group_id;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out private key buffer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid max private key size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out private key size");
    if (pub_key_out != NULL) {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pub_key_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid max public key size");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pub_key_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid out public key size");
    }

    // convert curve_name to pal_group_id
    switch (curve_name) {
        case KCM_SCHEME_EC_SECP256R1:
            pal_group_id = PAL_ECP_DP_SECP256R1;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF(true, KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE, "unsupported curve name");
    }

    // Generate keys
    pal_status = pal_ECKeyGenerateKey(pal_group_id, key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to generate keys");

    // Save private key to out buffer
    pal_status = pal_writePrivateKeyToDer(key_handle, priv_key_out, priv_key_max_size, priv_key_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to write private key to out buffer");

    if (pub_key_out != NULL) {
        // Save public key to out buffer
        pal_status = pal_writePublicKeyToDer(key_handle, pub_key_out, pub_key_max_size, pub_key_act_size_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to write public key to out buffer");
    }

    return KCM_STATUS_SUCCESS;
}

kcm_status_e cs_key_pair_generate(kcm_crypto_key_scheme_e curve_name, uint8_t *priv_key_out, size_t priv_key_max_size, size_t *priv_key_act_size_out, uint8_t *pub_key_out,
                                  size_t pub_key_max_size, size_t *pub_key_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;

    // Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    // Call to internal key_pair_generate
    kcm_status = cs_key_pair_generate_int(key_handle, curve_name, priv_key_out, priv_key_max_size, priv_key_act_size_out,
                                          pub_key_out, pub_key_max_size, pub_key_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate keys");

exit:
    //Free key handler
    if (key_handle != NULLPTR) {
        pal_ECKeyFree(&key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }
    return kcm_status;
}

static kcm_status_e cs_csr_generate_int(palECKeyHandle_t key_handle, const kcm_csr_params_s *csr_params,
                                        uint8_t *csr_buff_out, size_t csr_buff_max_size, size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "Failed to initialize x509 CSR handle");

    // Set CSR Subject
    pal_status = pal_x509CSRSetSubject(x509CSR_handle, csr_params->subject);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR Subject");

    // Set MD algorithm to SHA256 for the signature
    switch (csr_params->md_type) {
        case KCM_MD_SHA256:
            pal_md_type = PAL_SHA256;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_GOTO_IF(true, kcm_status = KCM_CRYPTO_STATUS_INVALID_MD_TYPE, exit, "MD type not supported");
    }
    pal_status = pal_x509CSRSetMD(x509CSR_handle, pal_md_type);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set MD algorithm");

    // Set keys into CSR
    pal_status = pal_x509CSRSetKey(x509CSR_handle, key_handle, NULLPTR);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to Set keys into CSR");

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
        pal_status = pal_x509CSRSetKeyUsage(x509CSR_handle, pal_key_usage);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR key usage");
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
        SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to set CSR extended key usage");
    }

    // Write the CSR to out buffer in DER format
    pal_status = pal_x509CSRWriteDER(x509CSR_handle, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to write the CSR to out buffer");

exit:
    //Free CSR handler
    if (x509CSR_handle != NULLPTR) {
        pal_x509CSRFree(&x509CSR_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((x509CSR_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free CSR handle failed ");
    }

    return kcm_status;
}

kcm_status_e cs_csr_generate(const uint8_t *priv_key, size_t priv_key_size, const kcm_csr_params_s *csr_params, uint8_t *csr_buff_out,
                             size_t csr_buff_max_size, size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private key size");

    // Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    // Parse private key from DER format
    pal_status = pal_parseECPrivateKeyFromDER(priv_key, priv_key_size, key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((PAL_SUCCESS != pal_status), kcm_status = cs_error_handler(pal_status), exit, "Failed to parse private key from DER format");

    // Call to internal csr_generate
    kcm_status = cs_csr_generate_int(key_handle, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate csr");

exit:
    //Free key handler
    if (key_handle != NULLPTR) {
        pal_ECKeyFree(&key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }
    return kcm_status;
}
kcm_status_e cs_generate_keys_and_csr(kcm_crypto_key_scheme_e curve_name, const kcm_csr_params_s *csr_params, uint8_t *priv_key_out,
                                      size_t priv_key_max_size, size_t *priv_key_act_size_out, uint8_t *pub_key_out,
                                      size_t pub_key_max_size, size_t *pub_key_act_size_out, uint8_t *csr_buff_out,
                                      const size_t csr_buff_max_size, size_t *csr_buff_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palECKeyHandle_t key_handle = NULLPTR;

    // Create new key handler
    pal_status = pal_ECKeyNew(&key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((PAL_SUCCESS != pal_status), cs_error_handler(pal_status), "pal_ECKeyNew failed");

    // Call to internal key_pair_generate
    kcm_status = cs_key_pair_generate_int(key_handle, curve_name, priv_key_out, priv_key_max_size, priv_key_act_size_out, pub_key_out, pub_key_max_size, pub_key_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate keys");

    // Call to internal csr_generate
    kcm_status = cs_csr_generate_int(key_handle, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate csr");

exit:
    //Free key handler
    if (key_handle != NULLPTR) {
        pal_ECKeyFree(&key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle != NULLPTR && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Free key handle failed ");
    }
    return kcm_status;
}
