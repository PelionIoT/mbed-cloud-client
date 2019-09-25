// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#ifndef __PSA_DRIVER_H__
#define __PSA_DRIVER_H__

#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "psa/crypto.h"

/*PSA key MIN and MAX IDs for psa crypto */
/*Current range 0x1 to 0x2800*/
#define  PSA_CRYPTO_MIN_ID_VALUE             0x1
#define  PSA_CRYPTO_NUM_OF_ID_ENTRIES        0x2800
#define  PSA_CRYPTO_MAX_ID_VALUE             PSA_CRYPTO_MIN_ID_VALUE + PSA_CRYPTO_NUM_OF_ID_ENTRIES - 1 //0x2800


/*PSA key MIN and MAX IDs for psa protected storage*/
/*Current range 0x2801 to 0x5000*/

/*PSA PS reserved range 0x2801 - 0x2900*/
#define PSA_PS_MIN_RESERVED_VALUE           PSA_CRYPTO_MAX_ID_VALUE + 0x1   //0x2801
#define PSA_PS_NUM_OF_RESERVED_ID_ENTRIES   0x100
#define PSA_PS_MAX_RESERVED_VALUE           PSA_PS_MIN_RESERVED_VALUE + PSA_PS_NUM_OF_RESERVED_ID_ENTRIES - 1  //0x2900

/*PSA PS free id range 0x2901-0x5000 */
#define PSA_PS_MIN_ID_VALUE                 PSA_PS_MAX_RESERVED_VALUE + 1//0x2901
#define PSA_PS_NUM_OF_FREE_ID_ENTRIES       0x2700 
#define PSA_PS_MAX_ID_VALUE                 PSA_PS_MIN_ID_VALUE + PSA_PS_NUM_OF_FREE_ID_ENTRIES - 1 //0x5000

//List of reserved ids:
#define PSA_PS_LAST_USED_CRYPTO_ID          PSA_PS_MIN_RESERVED_VALUE


/* invalid id number value */
#define PSA_INVALID_ID_NUMBER          0

/* invalid key handle value */
#define PSA_CRYPTO_INVALID_KEY_HANDLE         0


/******** PSA PS related flags*****/
/* Bits 8-11 :protected storage flags
*/
/*
* Write once flag.
* When the flag is used, the item can only be written once and cannot be removed.
*/
#define PSA_PS_WRITE_ONCE_FLAG         (1 << 0)

/*
* Confidentiality (encryption) flag.
*/
#define PSA_PS_CONFIDENTIALITY_FLAG    (1 << 1)

/*
* Replay protection flag.
* When this flag is used, the item cannot be physically removed (outside of psa_ps_remove API).
*/
#define PSA_PS_REPLAY_PROTECTION_FLAG  (1 << 2)
/*
* Mask of protected storage flags
*/
#define PSA_PS_PROTECTED_STORAGE_FLAGS_MASK 0x0000000F

/*************************************/


/******** PSA Crypto related flags*****/
//Location flag define by bits : 0-3 
/*
* PSA Crypto Secure element location flag.
*/
#define PSA_CRYPTO_SECURE_ELEMENT_LOCATION_FLAG  (1 << 1)
/*
* PSA location flag.
*/
#define PSA_CRYPTO_PSA_LOCATION_FLAG  (1 << 0)

//Item type flag flag defined by bits : 4-7 
/**
* PSA Crypto private key flag
*/
#define PSA_CRYPTO_PRIVATE_KEY_FLAG  (1 << 4)
/*
* PSA Crypto public key  flag
*/
#define PSA_CRYPTO_PUBLIC_KEY_FLAG  (1 << 5)
/**
* PSA Crypto certificate flag
*/
#define PSA_CRYPTO_CERTIFICATE_FLAG  (1 << 6)

/**
* PSA Crypto item type mask
*/
#define PSA_CRYPTO_TYPE_MASK_FLAG 0x000000F0
/**
* PSA Crypto item location mask
*/
#define PSA_CRYPTO_LOCATION_MASK_FLAG 0x00000000F



/******** PSA Crypto related declaration*****/
/**
* Initiates the PSA crypto module.
*
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_init(void);

/**
* Generates a new private and public keys based on an existing key's attributes and returns it's opened handle.
*
*    @param[in] exist_prv_ksa_id  the KSA PSA id of existing private key.
*    @param[in] exist_pub_ksa_id  the KSA PSA id of existing public key.
*    @param[out] prv_ksa_id  The KSA PSA id of the new generated private key.
*    @param[out] pub_ksa_id  The KSA PSA id of the new generated public key.
*    @param[out] prv_psa_key_handle  The handle of the new generated private key.
*    @param[out] pub_psa_key_handle  The handle of the new generated public key.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_generate_keys_from_existing_ids(const uint16_t exist_prv_ksa_id,
                                                            const uint16_t exist_pub_ksa_id,
                                                            uint16_t* prv_ksa_id,
                                                            uint16_t* pub_ksa_id,
                                                            psa_key_handle_t* prv_psa_key_handle,
                                                            psa_key_handle_t* pub_psa_key_handle);

/**
* Exports a data from PSA crypto module according to its PSA id.
* If key that associated with ksa_id is private key, the function exports from the private key its public key and returns its size.
*
*    @param[in] ksa_id  KSA PSA id number of the exported data.
*    @param[in/out] data  Pointer to the buffer provided for the exported data.
*    @param[in] data_size Size of the buffer for the exported data.
*    @param[out] actual_data_size  The actual size of the exported data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_export_data(const uint16_t ksa_id, void* data, size_t data_size, size_t* actual_data_size);

/**
* Finalizes the Crypto module.
*
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
void psa_drv_crypto_fini();



/**
* Gets a data from PS module according to its KSA PS id.
*
*    @param[in] ksa_id  KSA PS id number of the exported data.
*    @param[in] extra_flags  Extra flags of the data.
*    @param[in/out] data  Pointer to the buffer provided for the exported data.
*    @param[in] data_buffer_size Size of the buffer for the exported data.
*    @param[out] actual_data_size  The actual size of the exported data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_get_data(const uint16_t ksa_id, void* data, size_t data_buffer_size, size_t* actual_data_size);

/**
* Gets a data size from PS module according to its KSA PS id.
*
*    @param[in] ksa_id  KSA PS id number of the exported data.
*    @param[in] extra_flags  Extra flags of the data.
*    @param[out] actual_data_size  The actual data size.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_get_data_size(const uint16_t ksa_id, size_t* actual_data_size);

/**
* The function checks existence of a data associated with current ksa identifier.
* If the data not exists - the function set it to storage.
*    @param[in] ksa_id  KSA PS id number of the exported data.
*    @param[in] data  Pointer to the data.
*    @param[in] data_size Size of the data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_init_reserved_data(const uint16_t ksa_id, const void *data, size_t data_size);

/**
*
* The function used to perform direct write to PSA PS APIs with already known ksa_id
*
*    @param[in] ksa_id  KSA PS id number of the exported data.
*    @param[in] data  Pointer to the new data.
*    @param[in/out] data_size Size of the new data.
*    @param[in] extra flags Additional storage flags
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_set_data_direct(const uint16_t ksa_id, const void *data, size_t data_size, uint32_t extra_flags);


/******** Common declaration*********/
/**
*  Translates PSA errors returned by PSA crypto and PS modules to KCM error.
*
*    @param[in] psa_status psa error number.
*    @returns
*       KCM_STATUS_SUCCESS in case of PSA_SUCCESS, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_translate_to_kcm_error(psa_status_t psa_status);

/** Returns a key handle if exists
*
* @key_id[IN] The key identifier
* @key_handle_out[OUT] The key handle referred to the given key name, otherwise this out parameter value is undefined.
*                      This out parameter is valid only if the status is KCM_STATUS_SUCCESS.
*                      In any other case this out parameter value is undefined.
*
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_get_handle(uint16_t key_id, psa_key_handle_t *key_handle_out);

/** Closes a key handle
*
* @key_handle[IN] The key handle
*
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_close_handle(psa_key_handle_t key_handle);



#ifdef __cplusplus
}
#endif

#endif //__PSA_DRIVER_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
