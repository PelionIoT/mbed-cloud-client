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

#include <stdlib.h>
#include "pv_error_handling.h"
#include "fcc_status.h"
#include "fcc_output_info_handler.h"
#include "fcc_malloc.h"


//General error string
const char g_fcc_general_status_error_str[] = "General error:";

//fcc error strings
const char g_fcc_ca_error_str[] = "CA error:";
const char g_fcc_rot_error_str[] = "Root of trust error:";
const char g_fcc_entropy_error_str[] = "Entropy error:";
const char g_fcc_disabled_error_str[] = "Factory disabled error:";
const char g_fcc_invalid_certificate_error_str[] = "Certificate invalid:";
const char g_fcc_item_not_exists_error_str[] = "Item does not exist:";
const char g_fcc_meta_data_not_exists_error_str[] = "Meta data does not exist:";
const char g_fcc_meta_data_size_error_str[] = "Meta data does not exist:";
const char g_fcc_wrong_item_size_error_str[] = "Item size is wrong:";
const char g_fcc_empty_item_error_str[] = "Item empty:";
const char g_fcc_uri_wrong_format_error_str[] = "URI format incorrect:";
const char g_fcc_first_to_claim_not_allowed_error_str[] = "first to claim not allowed:";
const char g_fcc_wrong_utc_offset_value_error_str[] = "UTC offset incorrect:";
const char g_fcc_wrong_bootstrap_use_value_error_str[] = "Bootstrap mode value incorrect:";
const char g_fcc_not_permitted_error_str[] = "Operation not permitted:";
const char g_fcc_wrong_ca_certificate_error_str[] = "Validation of CA certificate failed:";
const char g_fcc_invalid_cn_certificate_error_str[] = "Certificate CN attribute invalid:";
const char g_fcc_crypto_public_key_correlation_error_str[] = "Certificate public key validation failed:";
const char g_fcc_internal_storage_error_str[] = "Internal storage error:";

//kcm crypto error strings
const char g_fcc_kcm_file_error_str[] = "File operation general error:";
const char g_fcc_kcm_invalid_file_version_str[] = "File version invalid:";
const char g_fcc_kcm_file_data_corrupted_str[] = "File data corrupted:";
const char g_fcc_kcm_file_name_corrupted_str[] = "File name corrupted:";
const char g_fcc_kcm_not_initialized_str[] = "KCM not initialized:";
const char g_fcc_kcm_close_incomplete_chain_str[] = "Closing incomplete KCM chain:";
const char g_fcc_kcm_invalid_chain_str[] = "Corrupted certificate chain file:";
const char g_fcc_kcm_invalid_num_of_cert_in_chain_str[] = "Invalid number of certificate in chain:";
const char g_fcc_kcm_file_exist_error_str[] = "Data already exists:";
const char g_fcc_kcm_file_name_too_long_error_str[] = "File name too long:";
const char g_fcc_crypto_kcm_error_str[] = "KCM crypto error:";
const char g_fcc_crypto_empty_item_error_str[] = "Item data empty:";
const char g_fcc_crypto_unsupported_hash_mode_error_str[] = "Hash mode unsupported:";
const char g_fcc_crypto_parsing_der_pivate_key_error_str[] = "Private key parse failed:";
const char g_fcc_crypto_parsing_der_public_key_error_str[] = "Public key parse failed:";
const char g_fcc_crypto_verify_private_key_error_str[] = "Private key verification failed:";
const char g_fcc_crypto_verify_public_key_error_str[] = "Public key verification failed:";
const char g_fcc_crypto_unsupported_curve_error_str[] = "Curve unsupported:";
const char g_fcc_crypto_parsing_der_cert_error_str[] = "Certificate parse failed:";
const char g_fcc_crypto_cert_expired_error_str[] = "Certificate expired:";
const char g_fcc_crypto_cert_future_error_str[] = "Certificate will be valid in the future:";
const char g_fcc_crypto_cert_md_alg_error_str[] = "Certificate MD algorithm error:";
const char g_fcc_crypto_cert_public_key_type_error_str[] = "Certificate public key type error:";
const char g_fcc_crypto_cert_public_key_error_str[] = "Certificate public key error:";
const char g_fcc_crypto_cert_not_trusted_error_str[] = "Certificate not trusted:";
const char g_fcc_crypto_invalid_x509_attr_error_str[] = "X509 attribute invalid:";
const char g_fcc_crypto_invalid_pk_key_format_error_str[] = "Public key format invalid:";
const char g_fcc_crypto_invalid_public_key_error_str[] = "Public key invalid:";
const char g_fcc_crypto_ecp_invalid_key_error_str[] = "EC key invalid:";
const char g_fcc_crypto_pk_key_invalid_version_error_str[] = "Public key version invalid:";
const char g_fcc_crypto_pk_password_requerd_error_str[] = "Public key password required:";
const char g_fcc_crypto_unknown_pk_algorithm_error_str[] = "Public key algorithm unknown:";
const char g_fcc_crypto_chain_validation_error_str[] = "Chain validation error:";

//warning strings
const char g_fcc_item_not_set_warning_str[] = "Item not set:";

const char g_fcc_bootstrap_mode_false_warning_str[] = "Bootstrap mode not activated:";
const char g_fcc_self_signed_warning_str[] = "Certificate is self signed:";
const char g_fcc_item_is_empty_warning_str[] = "Item empty:";
const char g_fcc_redundant_item_warning_str[] = "Item redundant:";
const char g_fcc_cert_time_validity_warning_str[] = "Certificate validity cannot be checked:";
const char g_fcc_cert_validity_less_10_years_warning_str[] = "Certificate validity is less than 10 years:";
const char g_fcc_ca_identifier_warning_str[] = "CA identifier wasn't set properly:";

fcc_output_info_s g_output_info;


/**  The function frees all allocated buffers
* @param output_warning_info[in]          The pointer to created fcc_warning_info_s structure
*/
static void fcc_free_list_of_warnings(fcc_warning_info_s  *output_warning_info)
{
    fcc_warning_info_s *current_node = output_warning_info;
    fcc_warning_info_s *next_node = output_warning_info->next;

    while (current_node != NULL) {
        if (current_node->warning_info_string != NULL) {
            fcc_free(current_node->warning_info_string);
        }
        fcc_free(current_node);
        current_node = next_node;
        if (current_node != NULL) {
            next_node = current_node->next;
        }
    }
}
/**  The function combines message string info and failed item, and sets it to passed pointer.
* @param message_string[in]          The message string - error or warning
* @param failed_item_name[in]        The name of item.
* @param failed_item_name_size[in]   The size of item's name.
* @param out_string[in/out]          The output string where the combined message should be copied.
*/
static fcc_status_e fcc_set_output_string_info(const char *message_string, const uint8_t *failed_item_name, size_t failed_item_name_size, char **out_string)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Allocate memory for error info
    *out_string = fcc_malloc(strlen(message_string) + failed_item_name_size + 1); // 1 char for '\0'
    SA_PV_ERR_RECOVERABLE_RETURN_IF((out_string == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, "Failed to allocate buffer for output info");

    //Copy to  the global structure error string info
    strcpy((*out_string), message_string);

    //Copy to  the global structure the name of failed item if it exists.
    if (failed_item_name != NULL) {
        memcpy((uint8_t*)(*out_string) + strlen(message_string), failed_item_name, failed_item_name_size);
        //Set '\0' in the end of error string info
        (*out_string)[strlen(message_string) + failed_item_name_size] = '\0';
    }


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

static size_t fcc_get_size_of_all_warning_strings()
{
    fcc_warning_info_s *current_node = g_output_info.head_of_warning_list;
    size_t size_of_all_warning_strings = 0;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    while (current_node != NULL) {
        size_of_all_warning_strings += strlen(current_node->warning_info_string);
        current_node = current_node->next;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return size_of_all_warning_strings;
}

static bool copy_all_warning_to_buffer(char *out_warning_string, size_t size_of_out_warning_string)
{
    fcc_warning_info_s *current_node = g_output_info.head_of_warning_list;
    size_t length_of_iterated_strings = 0;

    memset(out_warning_string, 0, size_of_out_warning_string);

    while (current_node != NULL) {
        //Calculate size of current warning
        if (length_of_iterated_strings + strlen(current_node->warning_info_string) + 1 > size_of_out_warning_string) {
            return false;
        }
        strcpy(out_warning_string + length_of_iterated_strings, current_node->warning_info_string);
        //Set '\n' in the end of warning string info
        (out_warning_string)[length_of_iterated_strings + strlen(current_node->warning_info_string)] = '\n';
        length_of_iterated_strings += strlen(current_node->warning_info_string) + 1;
        current_node = current_node->next;
    }
    //Increase the size for '\0'
    if (length_of_iterated_strings >= size_of_out_warning_string) {
        return false;
    }
    (out_warning_string)[length_of_iterated_strings] = '\0';

    return true;
}
/**  The function returns error string according to passed fcc_status.
* @param fcc_status[in]          The fcc_status
*
*/

char* fcc_get_fcc_error_string(fcc_status_e fcc_status)
{
    SA_PV_LOG_TRACE_FUNC_ENTER("fcc_status is %d", fcc_status);
    char *fcc_error_string = NULL;

    switch (fcc_status) {
        case FCC_STATUS_ERROR:
        case FCC_STATUS_MEMORY_OUT:
        case FCC_STATUS_INVALID_PARAMETER:
        case FCC_STATUS_KCM_ERROR:
        case FCC_STATUS_BUNDLE_ERROR:
        case FCC_STATUS_BUNDLE_RESPONSE_ERROR:
        case FCC_STATUS_BUNDLE_UNSUPPORTED_GROUP:
        case FCC_STATUS_BUNDLE_INVALID_SCHEME:
        case FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS:
        case FCC_STATUS_BUNDLE_INVALID_GROUP:
        case FCC_STATUS_KCM_STORAGE_ERROR:
        case FCC_STATUS_KCM_FILE_EXIST_ERROR:
        case FCC_STATUS_NOT_INITIALIZED:
        case FCC_STATUS_OUTPUT_INFO_ERROR:
        case FCC_STATUS_WARNING_CREATE_ERROR:
        case FCC_STATUS_INVALID_CERT_ATTRIBUTE:
        case FCC_STATUS_INTERNAL_ITEM_ALREADY_EXIST:
            fcc_error_string = (char*)g_fcc_general_status_error_str;
            break;
        case FCC_STATUS_CA_ERROR:
            fcc_error_string = (char*)g_fcc_ca_error_str;
            break;
        case FCC_STATUS_ROT_ERROR:
            fcc_error_string = (char*)g_fcc_rot_error_str;
            break;
        case FCC_STATUS_STORE_ERROR:
            fcc_error_string = (char*)g_fcc_internal_storage_error_str;
            break;
        case FCC_STATUS_KCM_CRYPTO_ERROR:
            fcc_error_string = (char*)g_fcc_crypto_kcm_error_str;
            break;
        case FCC_STATUS_INVALID_CERTIFICATE:
            fcc_error_string = (char*)g_fcc_invalid_certificate_error_str;
            break;
        case FCC_STATUS_INVALID_LWM2M_CN_ATTR:
            fcc_error_string = (char*)g_fcc_invalid_cn_certificate_error_str;
            break;
        case FCC_STATUS_ENTROPY_ERROR:
            fcc_error_string = (char*)g_fcc_entropy_error_str;
            break;
        case FCC_STATUS_FACTORY_DISABLED_ERROR:
            fcc_error_string = (char*)g_fcc_disabled_error_str;
            break;
        case FCC_STATUS_ITEM_NOT_EXIST:
            fcc_error_string = (char*)g_fcc_item_not_exists_error_str;
            break;
        case FCC_STATUS_WRONG_ITEM_DATA_SIZE:
            fcc_error_string = (char*)g_fcc_wrong_item_size_error_str;
            break;
        case FCC_STATUS_EMPTY_ITEM:
            fcc_error_string = (char*)g_fcc_empty_item_error_str;
            break;
        case FCC_STATUS_URI_WRONG_FORMAT:
            fcc_error_string = (char*)g_fcc_uri_wrong_format_error_str;
            break;
        case FCC_STATUS_FIRST_TO_CLAIM_NOT_ALLOWED:
            fcc_error_string = (char*)g_fcc_first_to_claim_not_allowed_error_str;
            break;
        case FCC_STATUS_BOOTSTRAP_MODE_ERROR:
            fcc_error_string = (char*)g_fcc_wrong_bootstrap_use_value_error_str;
            break;
        case FCC_STATUS_UTC_OFFSET_WRONG_FORMAT:
            fcc_error_string = (char*)g_fcc_wrong_utc_offset_value_error_str;
            break;
        case FCC_STATUS_INVALID_CA_CERT_SIGNATURE:
            fcc_error_string = (char*)g_fcc_wrong_ca_certificate_error_str;
            break;
        case FCC_STATUS_EXPIRED_CERTIFICATE:
            fcc_error_string = (char*)g_fcc_crypto_cert_expired_error_str;
            break;
        case FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR:
            fcc_error_string = (char*)g_fcc_crypto_public_key_correlation_error_str;
            break;
        case FCC_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
            fcc_error_string = (char*)g_fcc_crypto_chain_validation_error_str;
            break;
        default:
            fcc_error_string = (char*)NULL;
            break;
    }
    if (fcc_error_string != NULL) {
        SA_PV_LOG_TRACE_FUNC_EXIT("fcc_error_string is %s", fcc_error_string);
    }
    return fcc_error_string;
}

/**  The function returns error string according to passed kcm_status.
* @param kcm_status[in]          The kcm_status
*
*/

char* fcc_get_kcm_error_string(kcm_status_e kcm_status)
{
    SA_PV_LOG_TRACE_FUNC_ENTER("kcm_status is %d", kcm_status);

    char *kcm_error_string = NULL;

    switch (kcm_status) {
        case KCM_STATUS_ERROR:
        case KCM_STATUS_INVALID_PARAMETER:
        case KCM_STATUS_INSUFFICIENT_BUFFER:
        case KCM_STATUS_OUT_OF_MEMORY:
        case KCM_STATUS_INVALID_FILE_ACCESS_MODE:
        case KCM_STATUS_UNKNOWN_STORAGE_ERROR:
        case KCM_CRYPTO_STATUS_INVALID_MD_TYPE:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE:
        case KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR:
        case KCM_CRYPTO_STATUS_INVALID_OID:
        case KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT:
            kcm_error_string = (char*)g_fcc_general_status_error_str;
            break;
        case KCM_STATUS_STORAGE_ERROR:
            kcm_error_string = (char*)g_fcc_kcm_file_error_str;
            break;
        case KCM_STATUS_INVALID_FILE_VERSION:
            kcm_error_string = (char*)g_fcc_kcm_invalid_file_version_str;
            break;
        case KCM_STATUS_FILE_CORRUPTED:
            kcm_error_string = (char*)g_fcc_kcm_file_data_corrupted_str;
            break;
        case KCM_STATUS_NOT_INITIALIZED:
            kcm_error_string = (char*)g_fcc_kcm_not_initialized_str;
            break;
        case KCM_STATUS_CLOSE_INCOMPLETE_CHAIN:
            kcm_error_string = (char*)g_fcc_kcm_close_incomplete_chain_str;
            break;
        case KCM_STATUS_CORRUPTED_CHAIN_FILE:
            kcm_error_string = (char*)g_fcc_kcm_invalid_chain_str;
            break;
        case KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN:
            kcm_error_string = (char*)g_fcc_kcm_invalid_num_of_cert_in_chain_str;
            break;
        case KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
            kcm_error_string = (char*)g_fcc_crypto_chain_validation_error_str;
            break;
        case KCM_STATUS_ITEM_NOT_FOUND:
            kcm_error_string = (char*)g_fcc_item_not_exists_error_str;
            break;
        case KCM_STATUS_META_DATA_NOT_FOUND:
            kcm_error_string = (char*)g_fcc_meta_data_not_exists_error_str;
            break;
        case KCM_STATUS_META_DATA_SIZE_ERROR:
            kcm_error_string = (char*)g_fcc_meta_data_size_error_str;
            break;
        case KCM_STATUS_NOT_PERMITTED:
            kcm_error_string = (char*)g_fcc_not_permitted_error_str;
            break;
        case KCM_STATUS_FILE_EXIST:
            kcm_error_string = (char*)g_fcc_kcm_file_exist_error_str;
            break;
        case KCM_STATUS_FILE_NAME_CORRUPTED:
            kcm_error_string = (char*)g_fcc_kcm_file_name_corrupted_str;
            break;
        case KCM_STATUS_ITEM_IS_EMPTY:
            kcm_error_string = (char*)g_fcc_crypto_empty_item_error_str;
            break;
        case KCM_STATUS_FILE_NAME_TOO_LONG:
            kcm_error_string = (char*)g_fcc_kcm_file_name_too_long_error_str;
            break;
        case KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE:
            kcm_error_string = (char*)g_fcc_crypto_unsupported_hash_mode_error_str;
            break;
        case KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY:
            kcm_error_string = (char*)g_fcc_crypto_parsing_der_pivate_key_error_str;
            break;
        case  KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY:
            kcm_error_string = (char*)g_fcc_crypto_parsing_der_public_key_error_str;
            break;
        case  KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED:
            kcm_error_string = (char*)g_fcc_crypto_verify_private_key_error_str;
            break;
        case  KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED:
            kcm_error_string = (char*)g_fcc_crypto_verify_public_key_error_str;
            break;
        case  KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE:
            kcm_error_string = (char*)g_fcc_crypto_unsupported_curve_error_str;
            break;
        case  KCM_CRYPTO_STATUS_PARSING_DER_CERT:
            kcm_error_string = (char*)g_fcc_crypto_parsing_der_cert_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_EXPIRED:
            kcm_error_string = (char*)g_fcc_crypto_cert_expired_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_FUTURE:
            kcm_error_string = (char*)g_fcc_crypto_cert_future_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_MD_ALG:
            kcm_error_string = (char*)g_fcc_crypto_cert_md_alg_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE:
            kcm_error_string = (char*)g_fcc_crypto_cert_public_key_type_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_PUB_KEY:
            kcm_error_string = (char*)g_fcc_crypto_cert_public_key_error_str;
            break;
        case  KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED:
            kcm_error_string = (char*)g_fcc_crypto_cert_not_trusted_error_str;
            break;
        case  KCM_CRYPTO_STATUS_INVALID_X509_ATTR:
            kcm_error_string = (char*)g_fcc_crypto_invalid_x509_attr_error_str;
            break;
        case KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT:
            kcm_error_string = (char*)g_fcc_crypto_invalid_pk_key_format_error_str;
            break;
        case KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY:
            kcm_error_string = (char*)g_fcc_crypto_invalid_public_key_error_str;
            break;
        case KCM_CRYPTO_STATUS_ECP_INVALID_KEY:
            kcm_error_string = (char*)g_fcc_crypto_ecp_invalid_key_error_str;
            break;
        case KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION:
            kcm_error_string = (char*)g_fcc_crypto_pk_key_invalid_version_error_str;
            break;
        case KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED:
            kcm_error_string = (char*)g_fcc_crypto_pk_password_requerd_error_str;
            break;
        case KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG:
            kcm_error_string = (char*)g_fcc_crypto_unknown_pk_algorithm_error_str;
            break;
        default:
            kcm_error_string = (char*)NULL;
            break;
    }

    if (kcm_error_string != NULL) {
        SA_PV_LOG_TRACE_FUNC_EXIT("kcm_error_string is %s", kcm_error_string);
    }
    return kcm_error_string;
}

fcc_output_info_s* get_output_info(void)
{
    return &g_output_info;
}

void  fcc_init_output_info_handler()
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    g_output_info.error_string_info = NULL;
    g_output_info.head_of_warning_list = NULL;
    g_output_info.tail_of_warning_list = NULL;
    g_output_info.size_of_warning_info_list = 0;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

void  fcc_clean_output_info_handler()
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    fcc_free(g_output_info.error_string_info);
    g_output_info.error_string_info = NULL;

    if (g_output_info.head_of_warning_list != NULL) {
        fcc_free_list_of_warnings(g_output_info.head_of_warning_list);
    }
    g_output_info.size_of_warning_info_list = 0;
    g_output_info.tail_of_warning_list = NULL;
    g_output_info.head_of_warning_list = NULL;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

fcc_status_e fcc_store_warning_info(const uint8_t *failed_item_name, size_t failed_item_name_size, const char *warning_string)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_warning_info_s *new_node = NULL;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((warning_string == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Warning string is empty");
    SA_PV_LOG_INFO_FUNC_ENTER("warning_string is %s", warning_string);
    //Check parameters (failed_item_name can be NULL)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((failed_item_name != NULL && failed_item_name_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong failed item name parameters");

    //Allocate new node
    new_node = (fcc_warning_info_s*)fcc_malloc(sizeof(fcc_warning_info_s));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((new_node == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, "Failed to allocate memory for new warning list");

    //Set the new node with warning info (message and item name)
    fcc_status = fcc_set_output_string_info(warning_string, failed_item_name, failed_item_name_size, &(new_node->warning_info_string));
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = FCC_STATUS_ERROR, exit_with_error, "Failed to set warning string info\n");

    //Update the list
    if (g_output_info.head_of_warning_list == NULL) {
        //In case this is the first node
        g_output_info.head_of_warning_list = g_output_info.tail_of_warning_list = new_node;
    } else {
        //In case this is an additional node
        g_output_info.tail_of_warning_list->next = new_node;
        g_output_info.tail_of_warning_list = new_node;
    }
    g_output_info.tail_of_warning_list->next = NULL;
    g_output_info.size_of_warning_info_list++;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return fcc_status;

exit_with_error:
    fcc_free(new_node);
    return fcc_status;
}

fcc_status_e fcc_bundle_store_error_info(const uint8_t *failed_item_name, size_t failed_item_name_size, kcm_status_e kcm_status)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    char *error_string_info = NULL;

    SA_PV_LOG_INFO_FUNC_ENTER("kcm_status is %d", kcm_status);

    //Check parameters (failed_item_name can be NULL)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_INVALID_PARAMETER, "The fcc_bundle_store_error_info should not be called with success status");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((failed_item_name != NULL && failed_item_name_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong failed item name parameters");

    //Get kcm error string
    error_string_info = fcc_get_kcm_error_string(kcm_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((error_string_info == NULL), fcc_status = FCC_STATUS_ERROR, "Failed to get kcm error string");

    //Store kcm error string with item name
    fcc_status = fcc_set_output_string_info(error_string_info, failed_item_name, failed_item_name_size, &(g_output_info.error_string_info));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = FCC_STATUS_ERROR, "Failed to set error string info ");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

fcc_status_e fcc_store_error_info(const uint8_t *failed_item_name, size_t failed_item_name_size, fcc_status_e fcc_status)
{
    fcc_status_e fcc_result = FCC_STATUS_SUCCESS;
    char *error_string_info = NULL;

    SA_PV_LOG_INFO_FUNC_ENTER("fcc_status is %d", fcc_status);
    //Check parameters (failed_item_name can be NULL)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status == FCC_STATUS_SUCCESS), FCC_STATUS_INVALID_PARAMETER, "The fcc_store_error_info should not be called with success status");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((failed_item_name != NULL && failed_item_name_size == 0), FCC_STATUS_INVALID_PARAMETER, "Wrong failed item name parameters");

    //Get fcc error string
    error_string_info = fcc_get_fcc_error_string(fcc_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((error_string_info == NULL), FCC_STATUS_ERROR, "Failed to get fcc error string");

    if (g_output_info.error_string_info == NULL) {
        //Store fcc error string with item name
        fcc_result = fcc_set_output_string_info(error_string_info, failed_item_name, failed_item_name_size, &(g_output_info.error_string_info));
        SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_result != FCC_STATUS_SUCCESS), FCC_STATUS_ERROR, "Failed to set error string info ");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return fcc_result;
}

char* fcc_get_output_error_info()
{
    char *error_info = NULL;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (g_output_info.error_string_info != NULL) {
        error_info = g_output_info.error_string_info;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return error_info;
}


char*  fcc_get_output_warning_info()
{
    char *warrning_string_collection = NULL;
    size_t size_of_warning_string_collection = 0;
    size_t total_size_of_strings_with_delimeters = 0;
    bool status = false;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (g_output_info.head_of_warning_list == NULL || g_output_info.size_of_warning_info_list == 0) {
        return NULL;
    } else {
        //Get size of all warning
        size_of_warning_string_collection = fcc_get_size_of_all_warning_strings();

        //total_size_of_strings_with_delimeters -size_of_warning_string_collection +add '\n'  - as delimiter between the warnings and '\0' in the end
        total_size_of_strings_with_delimeters = size_of_warning_string_collection + g_output_info.size_of_warning_info_list + 1;

        //Allocate memory  buffer for all warnings
        warrning_string_collection = fcc_malloc(total_size_of_strings_with_delimeters);
        if (warrning_string_collection == NULL) {
            SA_PV_LOG_INFO("Failed to allocate memory for warning strings");
            return warrning_string_collection;
        }
        status = copy_all_warning_to_buffer(warrning_string_collection, total_size_of_strings_with_delimeters);
        if (status != true) {
            fcc_free(warrning_string_collection);
            return NULL;
        }
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return warrning_string_collection;
}

bool fcc_get_warning_status()
{
    if (g_output_info.head_of_warning_list != NULL) {
        return true;
    } else {
        return false;
    }
}
