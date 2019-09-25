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
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#ifndef __STORAGE_ITEMS_PELION_SST_H__
#define __STORAGE_ITEMS_PELION_SST_H__

#include <inttypes.h>
#include "key_config_manager.h"
#include "kcm_defs.h"
#include "esfs.h"

#ifdef __cplusplus
extern "C" {
#endif

    //ESFS defines
#define STORAGE_FILENAME_MAX_SIZE ESFS_MAX_NAME_LENGTH

    typedef enum {
        STORE_ESFS_MD_TYPE_CHAIN_LEN,
        STORE_ESFS_MD_TYPE_MAX // can't be bigger than ESFS_MAX_TYPE_LENGTH_VALUES
    } store_esfs_meta_data_type_e;

#if ESFS_MAX_TYPE_LENGTH_VALUES < KCM_MD_TYPE_MAX_SIZE
#error "KCM_MD_TYPE_MAX_SIZE can't be greater than ESFS_MAX_TYPE_LENGTH_VALUES"
#endif

    typedef struct store_esfs_meta_data_ {
        store_esfs_meta_data_type_e type;
        size_t data_size;
        uint8_t *data;
    } store_esfs_meta_data_s;

    typedef struct store_esfs_meta_data_list_ {
        // allocate a single meta data for each type
        store_esfs_meta_data_s meta_data[STORE_ESFS_MD_TYPE_MAX];
        size_t meta_data_count;
    } store_esfs_meta_data_list_s;

    typedef struct store_esfs_file_ctx_ {
        esfs_file_t esfs_file_h;
        size_t file_size;
        bool is_file_size_checked;
    } store_esfs_file_ctx_s;

    /* === File Operations === */

    /** Create a new file
    *
    *   @param KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes.
    *   @param meta_data_list A pointer to structure with single meta data for each type
    *   @param is_factory A factory flag.
    *   @param is_encrypted Encryption flag
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_create(store_esfs_file_ctx_s *ctx,
                                     const uint8_t *file_name,
                                     size_t file_name_length,
                                     const store_esfs_meta_data_list_s *meta_data_list,
                                     bool is_factory,
                                     bool is_encrypted);

    /** Open existing file
    *
    *   @param KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_open(store_esfs_file_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length);

    /** Close file in storage
    *
    *   @param ctx KCM operation context.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_close(store_esfs_file_ctx_s *ctx);

    /** Write data to previously opened file in storage
    *
    *   @param ctx KCM operation context.
    *   @param data A pointer to memory with the data to write into the newly created file. Can be NULL if data_length is 0.
    *   @param data_length The data length in bytes. Can be 0 if we wish to write an empty file.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_write_with_ctx(store_esfs_file_ctx_s *ctx, const uint8_t *data, size_t data_length);


    /** Writes a new file to storage
    *
    *   @param ctx KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes.
    *   @param data A pointer to memory with the data to write into the newly created file. Can be NULL if data_length is 0.
    *   @param data_length The data length in bytes. Can be 0 if we wish to write an empty file.
    *   @param meta_data_list A pointer to structure with single meta data for each type
    *   @param is_factory True if KCM item is factory item, or false otherwise
    *   @param is_encrypted True if KCM item should be encrypted, or false otherwise
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_write(store_esfs_file_ctx_s *ctx,
                                    const uint8_t *file_name,
                                    size_t file_name_length,
                                    const uint8_t *data,
                                    size_t data_length,
                                    const store_esfs_meta_data_list_s *meta_data_list,
                                    bool is_factory,
                                    bool is_encrypted);


    /** Returns the size of the data in a file
    *
    *   @param ctx KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes
    *   @param file_size_out A pointer to hold the size of the data in the file
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_size_get(store_esfs_file_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, size_t *file_size_out);

    /** Reads data from a file.
    *
    *   @param ctx KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes
    *   @param buffer_out A pointer to memory buffer where the data will be read from the file. Can be NULL if buffer_size is 0.
    *   @param buffer_size The number of bytes to be read. Buffer must be big enough to contain this size. Can be 0 if we wish to read an empty file.
    *   @param buffer_actual_size_out The effective bytes size read from the file.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_read(store_esfs_file_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out);

    /** Returns the size of the data in a file. The file should be opened by storage_file_open()
    *
    *   @param ctx KCM operation context.
    *   @param file_size_out A pointer to hold the size of the data in the file
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_size_get_with_ctx(store_esfs_file_ctx_s *ctx, size_t *file_size_out);

    /** Reads data from a file. The file should be opened by storage_file_open().
    *
    *   @param ctx KCM operation context.
    *   @param buffer_out A pointer to memory buffer where the data will be read from the file. Can be NULL if buffer_size is 0.
    *   @param buffer_size The number of bytes to be read. Buffer must be big enough to contain this size. Can be 0 if we wish to read an empty file.
    *   @param buffer_actual_size_out The effective bytes size read from the file.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_read_with_ctx(store_esfs_file_ctx_s *ctx, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out);
    /** Deletes the file from storage
    *
    *   @param ctx KCM operation context.
    *   @param file_name A binary blob that uniquely identifies the file
    *   @param file_name_length The binary blob length in bytes
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_delete(store_esfs_file_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length);

    /** Get the size of the stored meta data type. The file should be opened by storage_file_open().
    *
    *   @param ctx KCM operation context.
    *   @param type the meta data type to get size for.
    *   @param metadata_size_out A pointer to hold the size of the meta data
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_get_meta_data_size(store_esfs_file_ctx_s *ctx, store_esfs_meta_data_type_e type, size_t *meta_data_size_out);

    /** Reads meta data into a kcm_meta_data
    *
    *   @param ctx KCM operation context.
    *   @param type the meta data type to get size for.
    *   @param buffer_out A pointer to memory buffer where the meta data will be read to.
    *   @param buffer_size The number of bytes to be read. Buffer must be big enough to contain this size.
    *   @param buffer_actual_size_out The effective bytes size read from the file.
    *
    *   @returns
    *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
    */
    kcm_status_e storage_file_read_meta_data_by_type(store_esfs_file_ctx_s *ctx, store_esfs_meta_data_type_e type, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out);

#ifdef __cplusplus
}
#endif
#endif //__STORAGE_ITEMS_PELION_SST_H__
#endif//MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
