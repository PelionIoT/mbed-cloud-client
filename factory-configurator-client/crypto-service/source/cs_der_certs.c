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
#include "cs_der_certs.h"
#include "cs_der_keys_and_csrs.h"
#include "cs_utils.h"
#include "stdbool.h"
#include "fcc_malloc.h"


static kcm_status_e cs_get_x509_cert_attribute_type(cs_certificate_attribute_type_e cs_attribute_type, palX509Attr_t *attribute_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;


    switch (cs_attribute_type) {
        case CS_CN_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_CN_ATTR;
            break;
        case CS_VALID_TO_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_VALID_TO;
            break;
        case CS_VALID_FROM_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_VALID_FROM;
            break;
        case CS_OU_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_OU_ATTR;
            break;
        case CS_SUBJECT_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_SUBJECT_ATTR;
            break;
        case CS_ISSUER_ATTRIBUTE_TYPE:
            *attribute_type = PAL_X509_ISSUER_ATTR;
            break;
        case CS_CERT_ID_ATTR:
            *attribute_type = PAL_X509_CERT_ID_ATTR;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_CRYPTO_STATUS_INVALID_X509_ATTR, "Invalid cert attribute");
    }

    return kcm_status;
}

kcm_status_e cs_is_self_signed_x509_cert(palX509Handle_t x509_cert, bool *is_self_signed)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    uint8_t *cert_subject = NULL;
    uint8_t *cert_issuer = NULL;
    size_t subject_size = 0, issuer_size = 0;

    //Self-signed certificate is certificate with subject attribute = issuer attribute
    //get and check issuer and subject sizes
    kcm_status = cs_attr_get_data_size_x509_cert(x509_cert, CS_SUBJECT_ATTRIBUTE_TYPE, &subject_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "get size PAL_X509_SUBJECT_ATTR failed");

    kcm_status = cs_attr_get_data_size_x509_cert(x509_cert, CS_ISSUER_ATTRIBUTE_TYPE, &issuer_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "get size PAL_X509_ISSUER_ATTR failed");

    //If issuer and subject attributes have different length it is not self-signed certificate
    if (subject_size != issuer_size) {
        *is_self_signed = false;
        return KCM_STATUS_SUCCESS;
    }

    //Get and check attributes values
    cert_subject = fcc_malloc(subject_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cert_subject == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit, "Allocate subject attribute failed");

    pal_status = pal_x509CertGetAttribute(x509_cert, PAL_X509_SUBJECT_ATTR, cert_subject, subject_size, &subject_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), exit, "pal_x509CertGetAttribute PAL_X509_SUBJECT_ATTR failed %d ", (int)cs_error_handler(pal_status));

    cert_issuer = fcc_malloc(issuer_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cert_subject == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit, "Allocate issuer attribute failed");

    pal_status = pal_x509CertGetAttribute(x509_cert, PAL_X509_ISSUER_ATTR, cert_issuer, issuer_size, &issuer_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), exit, "pal_x509CertGetAttribute PAL_X509_ISSUER_ATTR failed %d", (int)kcm_status);

    if (memcmp(cert_issuer, cert_subject, issuer_size) == 0) {
        *is_self_signed = true;
    } else {
        *is_self_signed = false;
    }

exit:
    fcc_free(cert_subject);
    fcc_free(cert_issuer);

    return kcm_status;
}

kcm_status_e cs_create_handle_from_der_x509_cert(const uint8_t *cert, size_t cert_length, palX509Handle_t *x509_cert_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert != NULL && cert_length == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid cert_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_cert_handler");

    //Allocate and Init certificate handler
    pal_status = pal_x509Initiate(x509_cert_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), cs_error_handler(pal_status), "pal_x509Initiate failed");

    if (cert != NULL) {
        //Parse Certificate.
        pal_status = pal_x509CertParse(*x509_cert_handle, cert, cert_length);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), exit, "pal_x509CertParse failed");
    }

exit:
    if (pal_status != FCC_PAL_SUCCESS) {
        pal_x509Free(x509_cert_handle);
    }

    return kcm_status;
}
kcm_status_e cs_add_to_chain_x509_cert(const uint8_t *cert, size_t cert_length, palX509Handle_t x509_chain_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid cert_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_chain_handle == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_chain_handle");

    //Parse Certificate.
    pal_status = pal_x509CertParse(x509_chain_handle, cert, cert_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), "pal_x509CertParse failed");

    return kcm_status;
}
kcm_status_e cs_close_handle_x509_cert(palX509Handle_t *x509_cert_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    pal_status = pal_x509Free(x509_cert_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), "pal_x509Free failed");

    return kcm_status;
}
kcm_status_e cs_check_der_x509_format(const uint8_t *cert, size_t cert_length)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    palX509Handle_t x509_cert = NULLPTR;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_length <= 0), KCM_STATUS_INVALID_PARAMETER, "Invalid cert_length");

    //Allocate and Init certificate handler
    pal_status = pal_x509Initiate(&x509_cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), cs_error_handler(pal_status), "pal_x509Initiate failed");

    //Parse Certificate.
    pal_status = pal_x509CertParse(x509_cert, cert, cert_length);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), exit, "pal_x509CertParse failed");

exit:
    pal_x509Free(&x509_cert);
    return kcm_status;
}

kcm_status_e cs_verify_x509_cert(palX509Handle_t x509_cert, palX509Handle_t x509_cert_chain)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    bool is_self_signed = false;
    palX509Handle_t x509_ca_cert = NULLPTR;


    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid cert handle");

    kcm_status = cs_is_self_signed_x509_cert(x509_cert, &is_self_signed);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Self signed verification failed");

    if (is_self_signed && x509_cert_chain == NULLPTR) { // Send the certificate itself as trusted chain
        x509_ca_cert = x509_cert;
    } else {
        x509_ca_cert = x509_cert_chain;
    }

    //Verify certificate using created certificate chain
    pal_status = pal_x509CertVerify(x509_cert, x509_ca_cert);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), exit, "pal_x509CertVerify failed %" PRIx32 "", pal_status);

exit:
    return kcm_status;
}

kcm_status_e  cs_attr_get_data_size_x509_cert(palX509Handle_t x509_cert,
                                              cs_certificate_attribute_type_e cs_attribute_type,
                                              size_t *size_of_attribute)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Attr_t attribute_type;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    uint8_t output_buffer;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((size_of_attribute == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid size_of_attribute pointer");

    kcm_status = cs_get_x509_cert_attribute_type(cs_attribute_type, &attribute_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_get_x509_cert_attribute_type failed");

    //Get the attribute size
    pal_status = pal_x509CertGetAttribute(x509_cert, attribute_type, &output_buffer, 0, size_of_attribute);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == FCC_PAL_SUCCESS), KCM_STATUS_ERROR, "Attribute size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_ERR_BUFFER_TOO_SMALL), kcm_status = cs_error_handler(pal_status), "Failed to get attribute size");


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
};

kcm_status_e  cs_attr_get_data_x509_cert(palX509Handle_t x509_cert,
                                         cs_certificate_attribute_type_e cs_attribute_type,
                                         uint8_t *attribute_output_buffer,
                                         size_t max_size_of_attribute_output_buffer,
                                         size_t *actual_size_of_attribute_output_buffer)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Attr_t attribute_type;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((attribute_output_buffer == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid output pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((actual_size_of_attribute_output_buffer == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid actual_size_of_output pointer");

    kcm_status = cs_get_x509_cert_attribute_type(cs_attribute_type, &attribute_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_get_x509_cert_attribute_type failed");

    //Get the attribute
    pal_status = pal_x509CertGetAttribute(x509_cert, attribute_type, attribute_output_buffer, max_size_of_attribute_output_buffer, actual_size_of_attribute_output_buffer);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), "pal_x509CertGetAttribute failed");

    return kcm_status;
};

kcm_status_e  cs_x509_cert_verify_der_signature(palX509Handle_t x509_cert, const unsigned char *hash, size_t hash_size, const unsigned char *signature, size_t signature_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid hash pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_size != KCM_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid hash digest size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid signature pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid signature size");

    //Verify signature
    pal_status = pal_verifySignature(x509_cert, PAL_SHA256, hash, hash_size, signature, signature_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), kcm_status = cs_error_handler(pal_status), "pal_verifySignature failed");

    return kcm_status;
}

kcm_status_e cs_child_cert_params_get(palX509Handle_t x509_cert, cs_child_cert_params_s *params_out)
{
    palStatus_t pal_status = FCC_PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid x509_cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((params_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer params_out");

    // Retrieve the signature
    pal_status = pal_x509CertGetAttribute(x509_cert, PAL_X509_SIGNATUR_ATTR, params_out->signature, sizeof(params_out->signature), &params_out->signature_actual_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), cs_error_handler(pal_status), "Failed getting signature");

    // Hash a SHA256 of the To Be Signed part of the X509 certificate
    // If we end up using more than on hash type we may retrieve it from x509_cert instead of hard coded PAL_SHA256
    pal_status = pal_x509CertGetHTBS(x509_cert, PAL_SHA256, params_out->htbs, sizeof(params_out->htbs), &params_out->htbs_actual_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), cs_error_handler(pal_status), "Failed Hashing TBS");

    return KCM_STATUS_SUCCESS;
}

