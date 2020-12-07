/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __ESFS_H
#define __ESFS_H

#include <stdint.h>
#include "pal.h"
#include "pal_Crypto.h"



#define ESFS_AES_NONCE_SIZE_BYTES   (8)

// This value can be reduced to 0 to save stack space, if no metadata is required.
// Beware that changing the values affects the format of the file.
#define ESFS_MAX_TYPE_LENGTH_VALUES (3)

#define ESFS_FILE_NAME_LENGTH       (9)

// The maximum length of the name in bytes.
#define ESFS_MAX_NAME_LENGTH            (1024)

// ESFS_FILE_NAME_LENGTH + dot + extension (for example:  123456789.txt)
#define ESFS_QUALIFIED_FILE_NAME_LENGTH       (ESFS_FILE_NAME_LENGTH + 4)

#define ESFS_CMAC_SIZE_IN_BYTES         (16)

typedef enum {
    ESFS_SUCCESS = 0,
    ESFS_INVALID_PARAMETER = 1,
    ESFS_INTERNAL_ERROR = 2,
    ESFS_BUFFER_TOO_SMALL = 3,
    ESFS_ERROR = 4 ,
    ESFS_EXISTS = 5,
    ESFS_NOT_EXISTS = 6,
    ESFS_HASH_CONFLICT = 7,
    ESFS_FILE_OPEN_FOR_READ = 8,
    ESFS_FILE_OPEN_FOR_WRITE = 9,
    ESFS_INVALID_FILE_VERSION = 10,
    ESFS_CMAC_DOES_NOT_MATCH = 11,
    ESFS_ERROR_MAXVAL = 0xFFFF
}esfs_result_e;

typedef enum {
    ESFS_USER_READ = 0x0001,
    ESFS_USER_WRITE = 0x0002,
    ESFS_USER_DELETE = 0x0004,
    ESFS_USER_EXECUTE = 0x0008,
    ESFS_OTHER_READ = 0x0010,
    ESFS_OTHER_WRITE = 0x0020,
    ESFS_OTHER_DELETE = 0x0040,
    ESFS_OTHER_EXECUTE = 0x0080,
    ESFS_ENCRYPTED = 0x0100,
    ESFS_FACTORY_VAL = 0x0200,
    ESFS_EXTENDED_ACL = 0x0400,
    ESFS_MAXVAL = 0xFFFF
}esfs_mode_e;

typedef enum {
    ESFS_READ = 1,    // This is the same as the standard "O_RDONLY"
    ESFS_WRITE = 2    // This is the same as the standard "O_WRONLY & O_APPEND"
}esfs_file_flag_e;

typedef struct {
    uint16_t type;
    uint16_t length_in_bytes;
    void *value;
} esfs_tlv_item_t;

typedef struct {
    uint16_t type;
    uint16_t length_in_bytes;
    // Position in bytes from the beginning of the of file.
    uint16_t position;
} esfs_tlvItem_t;

typedef struct {
    uint16_t number_of_items;
    esfs_tlvItem_t tlv_items[ESFS_MAX_TYPE_LENGTH_VALUES];
}esfs_tlv_properties_t;


typedef struct {
    palFileDescriptor_t file;
    esfs_file_flag_e file_flag;
    palAesHandle_t aes_ctx;
    palCMACHandle_t signature_ctx;  // NULL indicates no context.
    uint8_t nonce[ESFS_AES_NONCE_SIZE_BYTES];
    uint8_t cmac[ESFS_CMAC_SIZE_IN_BYTES]; // Saved on open/create; compared with on read
    uint16_t esfs_mode;
    uint16_t blob_name_length;
    char short_file_name[ESFS_QUALIFIED_FILE_NAME_LENGTH];
    esfs_tlv_properties_t tlv_properties;
    uint8_t file_invalid; // The file handle is invalid.
    // These are valid for files that are opened, not created.
    long current_read_pos;   // The byte position from the beginning of the data.
    size_t data_size;   // The size of the data only in bytes.
    int32_t file_size;  // Cache the physical file size on open.
}esfs_file_t;

// ESFS from which the enum values are in sync with those of PAL.
typedef enum {
    ESFS_SEEK_SET = PAL_FS_OFFSET_SEEKSET,    // Offset will be relative to the beginning of the file.
    ESFS_SEEK_CUR = PAL_FS_OFFSET_SEEKCUR,    // Ofset will be relative to the last position read.
    ESFS_SEEK_END = PAL_FS_OFFSET_SEEKEND     // Offset will be relative to the end of the file and must be zero or a negative number.
}esfs_seek_origin_e;

#ifdef __cplusplus
extern "C" {
#endif

/** 
* @brief esfs_init Must be called once after boot.
*  Initializes the file system so that it can be used.
*  It creates the working and backup folders if they do not exist.
*  If the factory_reset operation was not completed, esfs_init continues the operation.
*
* @returns ESFS_SUCCESS or an error code.
*
*/
esfs_result_e esfs_init(void);


/** 
* @brief esfs_finalize needs to be called before calling esfs_init again.
* @returns ESFS_SUCCESS.
*
*/
esfs_result_e esfs_finalize(void);


/**
* @brief esfs_factory_reset removes the files from the working folder
*  and creates a copy of the files that were created with ESFS_FACTORY_VAL set in the esfs_mode parameter in the working folder.
*  If the device is rebooted during the factory reset operation, ESFS resumes the operation when calling esfs_init after the reboot.
*
* @returns ESFS_SUCCESS or ESFS_ERROR.
*
*/
esfs_result_e esfs_factory_reset(void);


/** 
 * @brief esfs_reset resets ESFS to an empty state.
                Initializes the file system and formats the SD card if required. Also initializes the internal structures.
 *
 * @returns ESFS_SUCCESS or an error code.
 *
 */
esfs_result_e esfs_reset(void);

/**
 * @brief Creates a new file and opens it for writing. Returns an error if a file exists.
 *
 *
 * @param [in] name
 *               A binary blob that uniquely identifies the file.
 *
 * @param [in] name_length
 *               The size of the name in bytes. The minimum is 1 and the maximum is ESFS_MAX_NAME_LENGTH.
 *
 * @param  [in] meta_data
 *                A pointer to an array of TLVs structures with meta_data_qty members.
 *
 * @param  [in] meta_data_qty
 *                The number of TLVs in the array pointed by the meta_data parameter. The minimum is 0 and the maximum is ESFS_MAX_TYPE_LENGTH_VALUES.
 *
 * @param  [in] esfs_mode
 *      A bitmap combination of values from the enum EsfsMode.
 *
 * @param [out] esfs_file_t file_handle A handle to the created file open for write.
 *
 * @returns ESFS_SUCCESS The file handle can be used in other ESFS functions. It must be closed to release it.
 *          ESFS_INVALID_PARAMETER if the name, name_length, file_handle or meta_data_qty is not valid.
 *          ESFS_EXISTS if a file with the same blob is found in the file system.
 *          ESFS_HASH_CONFLICT if two different blobs result in the same short name.
 *
 *
 */
esfs_result_e esfs_create(const uint8_t * name, size_t name_length, const esfs_tlv_item_t *meta_data, size_t meta_data_qty, uint16_t esfs_mode, esfs_file_t *file_handle);

/**
 * @brief Opens a file for read.
 *
 *
 * @param [in] name
 *               A binary blob that uniquely identifies the file.
 *
 * @param [in] name_length
 *               The size of the name in bytes.
 *
 * @param  [out] esfs_mode
 *                A pointer to get the actual mode bits passed on file creation (see EfsFlags for bit values).
 *
 *
 * @param [out] file_handle A handle to the file for future use.
 *
 * @returns ESFS_SUCCESS or an error code.
 * ESFS_INVALID_PARAMETER if the name, name_length or file_handle is not valid.
 * ESFS_HASH_CONFLICT - A file with the same file name but a different name is found.
 * ESFS_CMAC_DOES_NOT_MATCH - The CMAC does not match. The file has possibly been tampered with.
 * ESFS_INVALID_FILE_VERSION  - The format is invalid. This may indicate that the file is corrupt or the firmware supports
 * a different file version from the one opened.
 * ESFS_NOT_EXISTS if the file does not exist.
 * If successful, the file handle can be used in other ESFS functions. It must be closed to release it.
 *
 *
 */
esfs_result_e esfs_open(const uint8_t * name, size_t name_length, uint16_t * esfs_mode, esfs_file_t *file_handle);

/**
 * @brief Close the file and invalidate the file handle.
 *
 * @param [in] file_handle The handle.
 *
 * @returns ESFS_SUCCESS or an error code.
 * ESFS_INVALID_PARAMETER if the file_handle is not correct.
 * ESFS_HASH_CONFLICT - Trying to open a file with the same file name but a different name.
 */
esfs_result_e esfs_close(esfs_file_t *file_handle);

/**
 * @brief Reads data from a previously opened file with parameter esfs_mode=EfsRead. Decrypt if required.
 *
 *
 * @param [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 *
 * @param  [in] buffer
 *                A pointer to the memory buffer where the data read from the file is stored.
 *
 * @param  [in] bytes_to_read
 *                The number of bytes to be read. The buffer must be big enough to contain this size.
 *
 *
 * @param [out] read_bytes
 *                The pointer to return the number of bytes actually read. Will be equal or smaller than bytes_to_read.
 *
 * @returns ESFS_SUCCESS 
 *          ESFS_INVALID_PARAMETER if the file_handle is not correct, buffer is null or read_bytes is null.
 *          ESFS_FILE_OPEN_FOR_WRITE if the file is after esfs_create and before esfs_close.
 *
 */
esfs_result_e esfs_read(esfs_file_t *file_handle, void *buffer, size_t bytes_to_read, size_t *read_bytes);

/**
 * @brief Returns the metadata properties (TLVs) associated with the file.
 *
 * @param [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 * @param [out] meta_data_properties
 *              A pointer to return the metadata properties.
 *
 * @returns ESFS_SUCCESS 
 *         ESFS_INVALID_PARAMETER if file_handle is not valid or meta_data_properties is null.
 *         ESFS_FILE_OPEN_FOR_WRITE if the file is after esfs_create and before esfs_close.
 *
 */
esfs_result_e esfs_get_meta_data_properties(esfs_file_t *file_handle, esfs_tlv_properties_t **meta_data_properties);
/**
 * @brief Reads a single metadata entry into a TLV.
 *
 * @param [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 * @param [in] index
 *                The index of the metadata if more than one meta data entry with the same type is present. 0 is the first one. 
 *                The index refers to an imaginary array that holds metadata entries of the same type only.
 *
 * @param [in,out] meta_data
 *                A pointer to an esfs_tlv_item_t structure with a valid *value pointing to a buffer aligned and big enough to hold the metadata.
 *                The type and length_in_bytes fields of the TLV should be filled before calling the function with the right values for the required metadata.
 *                The function will check the correctness of the fields.
 *                (See esfs_get_meta_data_buffer_size to calculate the required size.)
 *
 *
 *@returns ESFS_SUCCESS 
 *         ESFS_INVALID_PARAMETER if file_handle or meta_data is not valid or the index is out of bounds.
 *         ESFS_FILE_OPEN_FOR_WRITE if the file is after esfs_create and before esfs_close.
 *
 */
esfs_result_e esfs_read_meta_data(esfs_file_t *file_handle, uint32_t index, esfs_tlv_item_t *meta_data);

/**
 * @brief Change the current position for read. This function will return an error if used on a file open with EfsWrite mode
 * or the resulting position is out of the data range of the file.
 *
 *@param [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 *
 * @param  [in] offset
 *                The number of bytes to move the read position. It can be negative but must be in range of the data.
 *
 * @param  [in] whence
 *                The position to relate the calculation of the new position for read. Use EfsSEEK_SET to seek the read position offset bytes from the beginning of the file and
 *                EfsSEEK_CUR to change the read position offset bytes from the last read. The last read is in the beginning of the file after open.
 *
 * @param  [out] position
 *                  A pointer to an integer that will hold the read position after the seek. The pointer may be NULL if the position is not the desired one.
 *
 *@returns ESFS_SUCCESS
 *         ESFS_INVALID_PARAMETER if file_handle is not valid or the offset is out of bounds.
 *         ESFS_FILE_OPEN_FOR_WRITE if the file is after esfs_create and before esfs_close.
 *
 *
 */
esfs_result_e esfs_seek(esfs_file_t *file_handle, int32_t offset, esfs_seek_origin_e whence, uint32_t *position);

/**
 * @brief Removes the file from the file system.
 *
 *
 *@param [in] name
 *               A binary blob that uniquely identifies the file.
 *
 * @param [in] name_length
 *               The size of the name in bytes.
 * @returns ESFS_SUCCESS
 *          ESFS_NOT_EXISTS if the file does not exist.
 *          ESFS_INVALID_PARAMETER if name, name_length or file_handle is not valid.
 */
esfs_result_e esfs_delete(const uint8_t * name, size_t name_length);

/**
 * @brief Write data to the file. Encrypt if required.
 * This may leave the file in an unpredictable state on failure. If that happens, the file
 * will be deleted by efs_close. The data is only guaranteed to be flushed to the media on efs_close.
 *
 *
 * @param    [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 * @param    [in] buffer
 *               A pointer to memory buffer with the data to write.
 *
 * @param    [in] bytes_to_write
 *               The number of bytes to write from the buffer.
 *
 * @returns ESFS_SUCCESS
 *          ESFS_FILE_OPEN_FOR_READ if called after esfs_open (file opened for read).
 *          ESFS_INVALID_PARAMETER if file_handle is not correct, buffer is null or bytes_to_write == 0.
 *
 *
 */
esfs_result_e esfs_write(esfs_file_t *file_handle, const void *buffer, size_t bytes_to_write);

/**
 * @brief Returns the size of the data in the file.
 *
 * @param    [in] file_handle
 *               The handle obtained from a call to esfs_open.
 *
 * @param    [out] size_in_bytes
 *               A pointer to hold the size of the data in the file.
 *
 *
 * @returns ESFS_SUCCESS
 *          ESFS_INVALID_PARAMETER if file_handle is not valid.
 *
 *
 */
esfs_result_e esfs_file_size(esfs_file_t *file_handle, size_t *size_in_bytes);

#ifdef __cplusplus
}
#endif

#endif


