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



// ----------------------------------------------------------- Includes -----------------------------------------------------------

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif


#include "pal.h"
#include "esfs.h"
#include "esfs_file_name.h"

#include "mbed-trace/mbed_trace.h"


#include <string.h>  // For memcmp and strncat



// --------------------------------------------------------- Definitions ----------------------------------------------------------


#define TRACE_GROUP                     "esfs"  // Maximum 4 characters

// We do not really know what other uses (if any) the file system card will have.
// We will assume that it may contain other files and we will keep all ESFS files in one directory.
// A future enhancement could be to put files that are not to be removed at factory reset in a separate directory.
#if !defined(ESFS_WORKING_DIRECTORY)
#define ESFS_WORKING_DIRECTORY          "WORKING"
#endif

#if !defined(ESFS_BACKUP_DIRECTORY)
#define ESFS_BACKUP_DIRECTORY           "BACKUP"
#endif

#define FACTORY_RESET_DIR               "FR"
#define FACTORY_RESET_FILE              "fr_on"

// We choose a size that does not take up too much stack, but minimizes the number of reads.
#define ESFS_READ_CHUNK_SIZE_IN_BYTES   (64)

#define ESFS_BITS_IN_BYTE               (8)
#define ESFS_AES_BLOCK_SIZE_BYTES       (16)
#define ESFS_AES_IV_SIZE_BYTES          (16)
#define ESFS_AES_COUNTER_INDEX_IN_IV    ESFS_AES_NONCE_SIZE_BYTES
#define ESFS_AES_COUNTER_SIZE_BYTES     (8)
#define ESFS_AES_KEY_SIZE_BYTES         (16)
#define ESFS_AES_KEY_SIZE_BITS          (ESFS_AES_KEY_SIZE_BYTES * ESFS_BITS_IN_BYTE)

// Defines the size in bytes of buffers for AES encryption / decryption.
// In case we have to encrypt / decrypt a bigger amount of bytes, we loop over the buffer
// and encrypt / decrypt up to ESFS_AES_BUF_SIZE_BYTES bytes on each step
#define ESFS_AES_BUF_SIZE_BYTES         (256)

// This should be incremented when the file format changes
#define ESFS_FILE_FORMAT_VERSION        (1)

#define ESFS_FILE_COPY_CHUNK_SIZE       (256)

#define MAX_FULL_PATH_SIZE (PAL_MAX_FOLDER_DEPTH_CHAR + \
                            1 + \
                            PAL_MAX(sizeof(ESFS_BACKUP_DIRECTORY), sizeof(ESFS_WORKING_DIRECTORY)) + \
                            PAL_MAX(sizeof(FACTORY_RESET_DIR) + sizeof(FACTORY_RESET_FILE), ESFS_QUALIFIED_FILE_NAME_LENGTH))

static bool esfs_initialize = false;



// -------------------------------------------------- Functions Implementation ----------------------------------------------------


//      ---------------------------------------------------------------
//                              Helper Functions
//      ---------------------------------------------------------------


esfs_result_e esfs_init(void)
{
    esfs_result_e result = ESFS_SUCCESS;
    tr_info("esfs_init - enter");
    if (!esfs_initialize)
    {
        palStatus_t pal_result = PAL_SUCCESS;
        esfs_file_t file_handle = {0};
        char dir_path[MAX_FULL_PATH_SIZE] = { 0 };

        pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, dir_path);
        if (pal_result != PAL_SUCCESS)
        {
            tr_err("esfs_init() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }

        strncat(dir_path, "/" ESFS_WORKING_DIRECTORY, 1 + sizeof(ESFS_WORKING_DIRECTORY));

        //Looping on first file system operation to work around IOTMORF-914 - sd-driver initialization
        for(int i=0 ; i<100; i++)
        {
            // Create the esfs subfolder working
            pal_result = pal_fsMkDir(dir_path);
            if ((pal_result == PAL_SUCCESS) || (pal_result == PAL_ERR_FS_NAME_ALREADY_EXIST))
            {
                break;
            }
            tr_err("esfs_init() %d", i);
            pal_osDelay(50);

        }

        if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NAME_ALREADY_EXIST))
        {
                tr_err("esfs_init() - pal_fsMkDir() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
                result = ESFS_ERROR;
                goto errorExit;
        }

        pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, dir_path);
        if (pal_result != PAL_SUCCESS)
        {

            tr_err("esfs_init() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }

        strncat(dir_path, "/" ESFS_BACKUP_DIRECTORY, 1 + sizeof(ESFS_BACKUP_DIRECTORY));

        // Create the directory ESFS_BACKUP_DIRECTORY
        pal_result = pal_fsMkDir(dir_path);
        if (pal_result != PAL_SUCCESS)
        {
            // Any error apart from file exist returns error.
            if (pal_result != PAL_ERR_FS_NAME_ALREADY_EXIST)
            {
                tr_err("esfs_init() - pal_fsMkDir() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
                result = ESFS_ERROR;
                goto errorExit;
            }
        }

        // create the correct path for factory reset file fr_on
        strncat(dir_path, "/" FACTORY_RESET_DIR "/" FACTORY_RESET_FILE, 1 + sizeof(FACTORY_RESET_DIR) + 1 + sizeof(FACTORY_RESET_FILE));
        pal_result = pal_fsFopen(dir_path, PAL_FS_FLAG_READONLY, &(file_handle.file));
        // (res == PAL_SUCCESS) : flag file can be opened for reading --> file \FR\fr_on found
        //                        previous factory reset failed during execution
        // (res == PAL_ERR_FS_NO_FILE) : flag file was not found --> good scenario
        // (res != PAL_ERR_FS_NO_FILE) : file system problem
        if (pal_result == PAL_SUCCESS)
        {
            //  Close the file before factory reset
            pal_result = pal_fsFclose(&(file_handle.file));
            if (pal_result != PAL_SUCCESS)
            {
                tr_err("esfs_init() - unexpected filesystem behavior pal_fsFclose() failed with pal_status = 0x%x", (unsigned int)pal_result);
                result = ESFS_ERROR;
                goto errorExit;
            }
            // previous factory reset failed during execution - therefore we call this factory_reset again
            result = esfs_factory_reset();
            if (result != ESFS_SUCCESS)
            {
                tr_err("esfs_init() - esfs_factory_reset() failed with esfs_result_e = 0x%x", result);
                result = ESFS_ERROR;
                goto errorExit;
            }
        } else if (pal_result != PAL_ERR_FS_NO_FILE)
        {
            tr_err("esfs_init() - unexpected filesystem behavior pal_fsFopen() failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }

        esfs_initialize = true;
    }
    return ESFS_SUCCESS;

errorExit:
    return result;

}

esfs_result_e esfs_finalize(void)
{
    esfs_initialize = false;
    tr_info("esfs_finalize - enter");
    return ESFS_SUCCESS;
}

// Validate that a file handle has been initialized by create or open.
// Parameters : file_handle - [IN] A pointer to a file handle for which we calculate the size.
// Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_validate(esfs_file_t *file_handle)
{
    if(file_handle && file_handle->blob_name_length > 0)
    {
        return ESFS_SUCCESS;
    }
    else
    {
        return ESFS_ERROR;
    }
}


//Function   : esfs_not_encrypted_file_header_size
//
//Description: This function returns the size in bytes of the file header without the metadata values part.
//             This is actually the non-encrypted part of the file header.
//             It is useful for calculation the file pointer position for AES encryption / decryption which starts only from the
//             encrypted part of the file.
//
//Parameters : file_handle - [IN] A pointer to a file handle for which we calculate the size.
//
//Return     : The size in bytes of the non-encrypted part of the file header
static size_t esfs_not_encrypted_file_header_size(esfs_file_t *file_handle)
{
    esfs_tlv_properties_t *tlv_properties = &(file_handle->tlv_properties);

    return ( file_handle->blob_name_length         +                                              // Name length field
             sizeof(file_handle->blob_name_length) +                                              // Name field
             sizeof(uint16_t)                      +                                              // Version field
             sizeof(uint16_t)                      +                                              // Mode field
             (((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0) ? ESFS_AES_NONCE_SIZE_BYTES : 0) + // Nonce field [non mandatory field] 
             sizeof(tlv_properties->number_of_items)                                    +         // Metadata number of elements field
             (tlv_properties->number_of_items * sizeof(tlv_properties->tlv_items[0]))             // Metadata tlv headers
           );
}

// Returns the size in bytes of the file header.
// This can only be called after the header has been read.
// Parameters :
// file_handle - [IN] A pointer to a file handle for which we calculate the size.
static size_t esfs_file_header_size(esfs_file_t *file_handle)
{
    size_t metadata_size = 0;
    esfs_tlv_properties_t *tlv_properties = &file_handle->tlv_properties;

    for(int i = 0; i < tlv_properties->number_of_items; i++)
    {
        metadata_size += tlv_properties->tlv_items[i].length_in_bytes;
    }

    return esfs_not_encrypted_file_header_size(file_handle) + metadata_size;
}

// Helper function to calculate the cmac on data that is written.
// Parameters :
// pbuf        - [IN] A pointer to a buffer
// num_bytes   - [IN] number of bytes that we request to write.
// file_handle - [IN] A pointer to a file handle for which we calculate the size.
// Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_fwrite_and_calc_cmac(const void *pbuf, size_t num_bytes, esfs_file_t *file_handle)
{
    palStatus_t res = pal_CMACUpdate(file_handle->signature_ctx, pbuf, num_bytes);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_fwrite_and_calc_cmac() - pal_CMACUpdate failed with result = 0x%x", (unsigned int)res);
        return ESFS_ERROR;
    }

    size_t num_bytes_written;
    res = pal_fsFwrite(&file_handle->file, pbuf, num_bytes, &num_bytes_written);
    if(res != PAL_SUCCESS || num_bytes != num_bytes_written)
    {
        tr_err("esfs_fwrite_and_calc_cmac() - pal_fsFwrite failed, status = 0x%x, written bytes = %zu, expected = %zu",
                (unsigned int)res, num_bytes_written, num_bytes);
        return ESFS_ERROR;
    }

    return ESFS_SUCCESS;
}


// Helper function to start a cmac run.
// Moves the file position to the start of the file.
// Parameters :
// file_handle - [IN] A pointer to a file handle.
// If successful it creates a cmac context which must be destroyed with a call to esfs_cmac_finish
// Return     : ESFS_SUCCESS on success. Error code otherwise.
static esfs_result_e esfs_cmac_start(esfs_file_t *file_handle)
{
    unsigned char key[ESFS_CMAC_SIZE_IN_BYTES];

    // Get CMAC key from PAL
    palStatus_t res = pal_osGetDeviceKey(palOsStorageSignatureKey128Bit, &key[0], ESFS_CMAC_SIZE_IN_BYTES);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_start_cmac() - pal_osGetDeviceKey() failed with pal_status = 0x%x", (unsigned int)res);
        return  ESFS_ERROR;
    }

    // Start CMAC with the key. Initializes signature_ctx
    res = pal_CMACStart(&file_handle->signature_ctx, &key[0], 128, PAL_CIPHER_ID_AES);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_start_cmac() - pal_CMACStart() failed with pal_status = 0x%x", (unsigned int)res);
        return  ESFS_ERROR;
    }

    // Seek to the start of the file
    res = pal_fsFseek(&file_handle->file, 0, PAL_FS_OFFSET_SEEKSET);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_start_cmac() - pal_fsFseek() failed with pal status 0x%x", (unsigned int)res);

        // Clean up the cmac context
        size_t num_bytes;
        // Ignore error. Sets file_handle->signature_ctx to 0 on success
        (void)pal_CMACFinish(&file_handle->signature_ctx, &key[0], &num_bytes);
        return  ESFS_ERROR;
    }

    return  ESFS_SUCCESS;
}

// Helper function to read and calculate the cmac on data that is read.
// The function will not update the cmac if there is no CMAC context in the file handle.
// Updates the file position.
// Parameters :
// file_handle    - [IN]   A pointer to a file handle for which we calculate the cmac.
// pbuf           - [OUT]  A pointer to a buffer containing the data that is read.
// num_bytes      - [IN]   number of bytes that we request to read.
// num_bytes_read - [OUT]  A pointer to a location in which will be written the number of bytes actually read.
// Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_cmac_read(esfs_file_t *file_handle, void *pbuf, size_t num_bytes, size_t *num_bytes_read)
{
    palStatus_t res = pal_fsFread(&file_handle->file, pbuf, num_bytes, num_bytes_read);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_cmac_read() - pal_fsFread failed with status = 0x%x", (unsigned int)res);
        return ESFS_ERROR;
    }

    // Update the CMAC only if there is a context. (It is allowed to read the file without calculating CMAC if
    // it does not need to checked.)
    if(file_handle->signature_ctx)
    {
        res = pal_CMACUpdate(file_handle->signature_ctx, pbuf, *num_bytes_read);
        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_cmac_read() - pal_CMACUpdate failed with status = 0x%x", (unsigned int)res);
            return ESFS_ERROR;
        }
    }

    return ESFS_SUCCESS;
}


// Helper function to skip past a part of the file while calculating the cmac on the skipped data.
// Updates the file position.
// Parameters :
// file_handle - [IN]   A pointer to a file handle.
// to          - [IN]   The absolute position from the start of the file to which skip.
//                      It must be greater than the current position and no longer that the file size.
// Return     : ESFS_SUCCESS on success. Error code otherwise.
static esfs_result_e esfs_cmac_skip_to(esfs_file_t *file_handle, int32_t to)
{
    // Get current position
    int32_t current_pos;
    off_t pal_offset;
    palStatus_t res = pal_fsFtell(&file_handle->file, &pal_offset);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_cmac_skip_to() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)res);
        return  ESFS_ERROR;
    }
    current_pos = (int32_t)pal_offset;

    // Iterate over the rest of file in chunks to calculate the cmac
    // buffer will contain only data read form the file
    for (int32_t i = to - current_pos; i > 0; i -= ESFS_READ_CHUNK_SIZE_IN_BYTES)
    {
        // Read a chunk
        // Here we read the file as is - plain text or encrypted
        uint8_t buffer[ESFS_READ_CHUNK_SIZE_IN_BYTES];
        size_t num_bytes;
        esfs_result_e res = esfs_cmac_read(file_handle, buffer, PAL_MIN((size_t)i, ESFS_READ_CHUNK_SIZE_IN_BYTES), &num_bytes);
        if (res != ESFS_SUCCESS || num_bytes == 0)
        {
            tr_err("esfs_cmac_skip_to() failed  num_bytes bytes = %zu", num_bytes);
            return  ESFS_ERROR;
        }
     }
    return  ESFS_SUCCESS;
}

// Helper function to terminate a cmac run and return the resulting cmac.
// Parameters :
// file_handle - [IN]   A pointer to a file handle for which we calculate the cmac.
// pcmac       - [OUT]  A pointer to a buffer into which the cmac will be written. It must be at least ESFS_CMAC_SIZE_IN_BYTES.
// Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_cmac_finish(esfs_file_t *file_handle, unsigned char *pcmac)
{
    size_t num_bytes;

    // Sets file_handle->signature_ctx to 0 on success
    palStatus_t res = pal_CMACFinish(&file_handle->signature_ctx, pcmac, &num_bytes);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_finish_cmac() - pal_CMACFinish() failed with pal_status = 0x%x", (unsigned int)res);
        return  ESFS_ERROR;
    }
    return  ESFS_SUCCESS;
}

// Helper function to compare the passed cmac against the one in the file and to the one in the file descriptor
// and then return the file position in the passed value.
// Updates the file position.
// Parameters :
// file_handle - [IN]   A pointer to a file handle for which we check the cmac.
// pcmac       - [IN]   A pointer to a buffer containing the cmac that will be compared. It must be at least ESFS_CMAC_SIZE_IN_BYTES.
// position    - [IN]   The absolute position from the start of the file to which we restore the file position.
// Return     : ESFS_SUCCESS on success. Error code otherwise.
static esfs_result_e esfs_cmac_check_and_restore(esfs_file_t *file_handle, unsigned char *pcmac, int32_t position)
{
    // Read the signature from the file
    unsigned char file_cmac[ESFS_CMAC_SIZE_IN_BYTES];
    size_t num_bytes;
    palStatus_t res = pal_fsFread(&file_handle->file, &file_cmac[0], ESFS_CMAC_SIZE_IN_BYTES, &num_bytes);
    if (res != PAL_SUCCESS || num_bytes != ESFS_CMAC_SIZE_IN_BYTES)
    {
        tr_err("esfs_cmac_check_and_restore() - pal_fsFread() failed with pal result = 0x%x and num_bytes bytes = %zu", (unsigned int)res, num_bytes);
        return ESFS_ERROR;
    }
    // Compare the cmac that we read from the file with the one that is passed and check it against
    // the one recorded in esfs_open in order to verify that the file is the same as the one that was opened.
    if(memcmp(&file_cmac[0], pcmac, ESFS_CMAC_SIZE_IN_BYTES) != 0 ||
            memcmp(&file_cmac[0], &file_handle->cmac[0], ESFS_CMAC_SIZE_IN_BYTES) != 0)
    {
        tr_err("esfs_cmac_check_and_restore() - cmac that we read from the file does not match the one that we calculated");
        return ESFS_CMAC_DOES_NOT_MATCH;
    }

    // Set the file position to the byte indicated by position.
    res = pal_fsFseek(&file_handle->file, position, PAL_FS_OFFSET_SEEKSET);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_cmac_check_and_restore() - pal_fsFseek() failed with pal status 0x%x", (unsigned int)res);
        return ESFS_ERROR;
    }

    return  ESFS_SUCCESS;
}

//Function   : esfs_memcpy_reverse
//
//Description: This function copies the first <len_bytes> bytes from input buffer <src_ptr> to output buffer <dest_ptr> in
//             reversed order (e.g. '1' '2' '3' data array will be copied as '3' '2' '1').
//             Note: The function assumes that the memory areas of the input buffers src_ptr and dest_ptr do not overlap.
//
//Parameters : dest_ptr  - [IN / OUT] A pointer to the destination buffer to which bytes will be copied.
//             src_ptr   - [IN]       A pointer to the source buffer from which bytes will be copied.
//             len_bytes - [IN]       Number of bytes to be copied.
//
//Return     : A pointer to the output buffer <dest_ptr>
static void *esfs_memcpy_reverse(void *dest_ptr, const void *src_ptr, uint32_t len_bytes)
{
    uint8_t       *tmp_dest_ptr = (uint8_t *)dest_ptr;
    const uint8_t *tmp_src_ptr  = (const uint8_t *)src_ptr;


    // Make the reverse copy
    while(len_bytes > 0)
    {
        *(tmp_dest_ptr++) = *(tmp_src_ptr + len_bytes - 1);
        len_bytes--;
    }

    return dest_ptr;
}

//Function   : esfs_calc_file_pos_for_aes
//
//Description: This function calculates the file position for the purpose of AES encrypt / decrypt:
//             The returned position is relative to the beginning of the encrypted data.
//             The file is encrypted starting from the meta data part (the meta data values).
//
//Parameters : file_handle - [IN]  A pointer to a file handle on which we calculate the position.
//             position    - [OUT] A pointer to size_t to be filled in with the returned position.
//
//Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_calc_file_pos_for_aes(esfs_file_t *file_handle, size_t *position)
{
    palStatus_t pal_status = PAL_SUCCESS;
    size_t non_encrypt_size = 0;
    off_t pal_offset;

    *position = 0;

    // Get current position inside the file
    pal_status = pal_fsFtell(&file_handle->file, &pal_offset);
    if(pal_status != PAL_SUCCESS)
    {
        tr_err("esfs_calc_file_pos_for_aes() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)pal_status);
        return ESFS_ERROR;
    }
    *position = (size_t)pal_offset;

    // Calculate non_encrypt_size to be subtracted from position
    non_encrypt_size = esfs_not_encrypted_file_header_size(file_handle);

    if(*position < non_encrypt_size)
    {
        tr_err("esfs_calc_file_pos_for_aes() - Error. Position is in non encrypted part.");
        return ESFS_ERROR;
    }


    *position -= non_encrypt_size;


    return ESFS_SUCCESS;
}


//Function   : esfs_set_counter_in_iv_by_file_pos
//
//Description: This function fills in the last 8 bytes of the IV [iv128_arr] with the counter calculated according to
//             the input position.
//
//Parameters : position  - [IN]     The position in the file when count starts from the encrypted data part (the meta data values).
//             iv128_arr - [IN/OUT] A 16 bytes buffer holding the IV.
//                                  First 8 bytes contain the NONCE, and last 8 bytes will be filled in with the counter.
//
//Return     : ESFS_SUCCESS on success. Error code otherwise
static void esfs_set_counter_in_iv_by_file_pos(size_t position, uint8_t *iv128_arr)
{
    uint64_t counter = 0;


    // Calculate counter part of IV
    counter = (uint64_t)(position / ESFS_AES_BLOCK_SIZE_BYTES);


    // Copy the counter part to the IV
#if BIG__ENDIAN == 1
    memcpy(iv128_arr + ESFS_AES_COUNTER_INDEX_IN_IV, &counter, ESFS_AES_COUNTER_SIZE_BYTES);
#else
    esfs_memcpy_reverse(iv128_arr + ESFS_AES_COUNTER_INDEX_IN_IV, &counter, ESFS_AES_COUNTER_SIZE_BYTES);
#endif
}


//Function   : esfs_aes_enc_dec_by_file_pos
//
//Description: This function encrypts / decrypts data using AES-CTR.
//             This is the basic function used for AES encrypt / decrypt.
//             Due to the nature of AES-CTR which works on blocks, special handling is required in case the data in the file is not
//             on block boundaries. In this case we encrypt / decrypt this "partial block data" in a temporal buffer after copying
//             the data to the corresponding index inside this buffer. The rest of the data is being encrypted / decrypted normally.
//
//Parameters : aes_ctx     - [IN]  The per-initiated AES context.
//             buf_in      - [IN]  A buffer containing to data to be encrypted / decrypted.
//             buf_out     - [OUT] A buffer to be filled in with the encrypted / decrypted data.
//             len_bytes   - [IN]  Number of bytes to encrypt / decrypt.
//             position    - [IN]  The position in the file when count starts from the encrypted data part (the meta data values).
//             nonce64_ptr - [IN]  An 8 bytes buffer holding the NONCE part of the IV.
//
//Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_aes_enc_dec_by_file_pos( palAesHandle_t  aes_ctx,
                                                   const uint8_t  *buf_in,
                                                   uint8_t        *buf_out,
                                                   size_t          len_bytes,
                                                   size_t          position,
                                                   uint8_t        *nonce64_ptr
                                                 )
{
    palStatus_t pal_status = PAL_SUCCESS;

    uint8_t prev_remainder     = 0;  // Size in bytes of partial block PREVIOUSLY encrypted / decrypted
    uint8_t partial_block_size = 0;  // Size in bytes of partial block for NEXT encrypt / decrypt

    uint8_t partial_block_size_temp = 0;

    uint8_t partial_block_in[ESFS_AES_BLOCK_SIZE_BYTES]  = {0}; // Will contain data for next partial encrypt / decrypt
    uint8_t partial_block_out[ESFS_AES_BLOCK_SIZE_BYTES] = {0};

    uint8_t iv_arr[ESFS_AES_IV_SIZE_BYTES] = {0};   // Will contain nonce [bytes 0 - 7] and counter [bytes 8 - 15]


//    -------- partial_block_in:  Size = block_size [16 bytes]
//    |
//    |
//   \|/
//
//    -----------------------------------------------------------------------------------------
//    |                      |                                            |                   |
//    |  0  ...           0  |         Data copied form buf_in            |  0  ...        0  |
//    |                      |                                            |                   |
//    -----------------------------------------------------------------------------------------
//               ^                               ^                                ^
//               |                               |                                |
//               |                               |                                |
//               |                               |                                |
//        Size: prev_remainder                   |                          Size: might be 0
//                                               |
//                                               |
//                                       Size: partial_block_size
//                                       (might consume the buffer till its end)


    prev_remainder = (uint8_t)(position % ESFS_AES_BLOCK_SIZE_BYTES);

    partial_block_size_temp = (uint8_t)(ESFS_AES_BLOCK_SIZE_BYTES - prev_remainder);
    partial_block_size      = (uint8_t)PAL_MIN(partial_block_size_temp, len_bytes);

    // Prepare partial_block_in: Copy data for next encrypt / decrypt from buf_in to partial_block_in
    memcpy(partial_block_in + prev_remainder, buf_in, partial_block_size);

    // Prepare iv_arr: Copy nonce into bytes [0 - 7] of IV buffer
    memcpy(iv_arr, nonce64_ptr, ESFS_AES_NONCE_SIZE_BYTES);

    // Prepare iv_arr: Set counter in bytes [8 - 15] of IV buffer
    esfs_set_counter_in_iv_by_file_pos(position, iv_arr);


    // Encrypt / decrypt partial block [run on entire block, and copy later only desired part)
    pal_status = pal_aesCTRWithZeroOffset(aes_ctx, partial_block_in, partial_block_out, ESFS_AES_BLOCK_SIZE_BYTES, iv_arr);

    if(pal_status != PAL_SUCCESS)
    {
        tr_err("esfs_aes_enc_dec_by_file_pos() - pal_aesCTRWithZeroOffset() failed with pal_status = 0x%x", (unsigned int)pal_status);
        return ESFS_ERROR;
    }

    // Copy partial_block_out to buf_out
    memcpy(buf_out, partial_block_out + prev_remainder, partial_block_size);


    // Encrypt / decrypt the rest of the data
    if(len_bytes > partial_block_size)
    {
        // Set updated counter in bytes [8 - 15] of IV buffer
        esfs_set_counter_in_iv_by_file_pos(position + partial_block_size, iv_arr);

        pal_status = pal_aesCTRWithZeroOffset(aes_ctx, buf_in + partial_block_size, buf_out + partial_block_size, len_bytes - partial_block_size, iv_arr);

        if(pal_status != PAL_SUCCESS)
        {
            tr_err("esfs_aes_enc_dec_by_file_pos() - pal_aesCTRWithZeroOffset() failed with pal_status = 0x%x", (unsigned int)pal_status);
            return ESFS_ERROR;
        }
    }


    return ESFS_SUCCESS;
}


//Function   : esfs_read_and_decrypt
//
//Description: This function reads encrypted data from a file, decrypts it, and writes it into a buffer.
//
//Parameters : file_handle    - [IN]  A pointer to a file handle from which we read data.
//             buffer         - [IN]  The buffer to fill in with decrypted file data.
//             bytes_to_read  - [IN]  Number of bytes to read from the file.
//             read_bytes_ptr - [OUT] A pointer to size_t to be filled in with number of bytes actually read from the file.
//
//Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_read_and_decrypt(esfs_file_t *file_handle, void *buffer, size_t bytes_to_read, size_t *read_bytes_ptr)
{
    esfs_result_e result     = ESFS_SUCCESS;

    size_t position = 0;


    // Get file pointer position for AES - Must be done before calling pal_fsFread() which modifies the file pointer position
    result = esfs_calc_file_pos_for_aes(file_handle, &position);

    if(result != ESFS_SUCCESS)
    {
        tr_err("esfs_read_and_decrypt() - esfs_calc_file_pos_for_aes() failed with status = 0x%x", result);
        return result;
    }


    // Read file's encrypted data into buffer
    result = esfs_cmac_read(file_handle, buffer, bytes_to_read, read_bytes_ptr );

    if((result != ESFS_SUCCESS) || (*read_bytes_ptr != bytes_to_read))
    {
        tr_err("esfs_read_and_decrypt() - esfs_cmac_read() failed with ESFS_status = 0x%x", (unsigned int)result);
        return ESFS_ERROR;
    }


    // AES decrypt in-place - decrypt the encrypted data inside buffer, into buffer [out parameter]
    result = esfs_aes_enc_dec_by_file_pos(file_handle->aes_ctx, buffer, buffer, bytes_to_read, position, file_handle->nonce);

    if(result != ESFS_SUCCESS)
    {
        tr_err("esfs_read_and_decrypt() - esfs_aes_enc_dec_by_file_pos() failed with status = 0x%x", (unsigned int)result);
        return result;
    }


    return ESFS_SUCCESS;
}


//Function   : esfs_encrypt_fwrite_and_calc_cmac
//
//Description: This function takes a plain text buffer, encrypts it, writes the encrypted data to a file, and updates the
//             CMAC signature.
//
//             Since we cannot modify the data of the input buffer (const), this operation cannot be done in-place, so we need
//             to use another buffer for the encryption result. In order to avoid dynamically allocation, we use a buffer
//             of size ESFS_AES_BUF_SIZE_BYTES statically allocated on the stack. This forces us to encrypt and write in a loop -
//             each iteration encrypts and writes maximum size of ESFS_AES_BUF_SIZE_BYTES bytes.
//
//Parameters : buffer         - [IN]     The buffer to encrypt and write to the file.
//             bytes_to_write - [IN]     The number of bytes to write.
//             file_handle    - [IN]     A pointer to a file handle to which we write the data.
//
//Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_encrypt_fwrite_and_calc_cmac(const void *buffer, size_t bytes_to_write, esfs_file_t *file_handle)
{
    esfs_result_e result = ESFS_SUCCESS;

    size_t position    = 0;
    size_t remaining_bytes_to_write = bytes_to_write;

    const uint8_t *buffer_tmp_ptr = (uint8_t *)buffer;  // Will point to the next reading point in buffer as we read it

    uint8_t encrypted_data[ESFS_AES_BUF_SIZE_BYTES] = {0}; // Will hold encrypted data to be written to the file


    if(buffer == NULL)
    {
        tr_err("esfs_encrypt_fwrite_and_calc_cmac() - Bad arguments error. Input buffer is NULL.");
        return ESFS_ERROR;
    }


    // Get file pointer position for AES - Must be done before calling esfs_fwrite_and_calc_cmac() which modifies the file pointer position
    result = esfs_calc_file_pos_for_aes(file_handle, &position);

    if(result != ESFS_SUCCESS)
    {
        tr_err("esfs_encrypt_fwrite_and_calc_cmac() - esfs_calc_file_pos_for_aes failed with result=0x%x", result);
        return result;
    }


    // On every iteration in the loop, encrypt ESFS_AES_BUF_SIZE_BYTES bytes, and write them to the file
    while(remaining_bytes_to_write >= ESFS_AES_BUF_SIZE_BYTES)
    {
        // AES encrypt into encrypted_data
        result = esfs_aes_enc_dec_by_file_pos(file_handle->aes_ctx, buffer_tmp_ptr, encrypted_data, ESFS_AES_BUF_SIZE_BYTES, position, file_handle->nonce);

        if(result != ESFS_SUCCESS)
        {
            tr_err("esfs_encrypt_fwrite_and_calc_cmac() - esfs_aes_enc_dec_by_file_pos failed with result=0x%x", result);
            return result;
        }

        // Write the encrypted data to the file
        result = esfs_fwrite_and_calc_cmac(encrypted_data, ESFS_AES_BUF_SIZE_BYTES, file_handle);

        if((result != ESFS_SUCCESS))
        {
            tr_err("esfs_encrypt_fwrite_and_calc_cmac() - esfs_fwrite_and_calc_cmac() status = 0x%x", (unsigned int)result);

            // esfs_fwrite_and_calc_cmac() failed so we cannot be sure of the state of the file - mark the file as invalid
            file_handle->file_invalid = 1;

            return ESFS_ERROR;
        }

        position       += ESFS_AES_BUF_SIZE_BYTES;
        buffer_tmp_ptr += ESFS_AES_BUF_SIZE_BYTES;

        remaining_bytes_to_write -= ESFS_AES_BUF_SIZE_BYTES;
    }


    // AES encrypt the leftover of buffer
    if(remaining_bytes_to_write > 0)
    {
        // AES encrypt into encrypted_data
        result = esfs_aes_enc_dec_by_file_pos(file_handle->aes_ctx, buffer_tmp_ptr, encrypted_data, remaining_bytes_to_write, position, file_handle->nonce);

        if(result != ESFS_SUCCESS)
        {
            tr_err("esfs_encrypt_fwrite_and_calc_cmac() - esfs_aes_enc_dec_by_file_pos failed with result=0x%x", result);
            return result;
        }


        // Write the encrypted data to the file
        result = esfs_fwrite_and_calc_cmac(encrypted_data, remaining_bytes_to_write, file_handle);

        if((result != ESFS_SUCCESS))
        {
            tr_err("esfs_encrypt_fwrite_and_calc_cmac() - esfs_fwrite_and_calc_cmac() status = 0x%x", (unsigned int)result);

            // esfs_fwrite_and_calc_cmac() failed so we cannot be sure of the state of the file - mark the file as invalid
            file_handle->file_invalid = 1;

            return ESFS_ERROR;
        }
    }

    return ESFS_SUCCESS;
}


esfs_result_e esfs_reset(void)
{
    esfs_result_e result = ESFS_SUCCESS;
    palStatus_t pal_result = PAL_SUCCESS;
    char dir_path[MAX_FULL_PATH_SIZE] = { 0 };
    tr_info("esfs_reset - enter");
    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, dir_path);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_reset() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(dir_path, "/" ESFS_WORKING_DIRECTORY, 1 + sizeof(ESFS_WORKING_DIRECTORY));

    // delete the files in working dir
    pal_result = pal_fsRmFiles(dir_path);
    // the use case is that esfs folder may not exist
    if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NO_FILE) && (pal_result != PAL_ERR_FS_NO_PATH))
    {
        tr_err("esfs_reset() - pal_fsRmFiles(ESFS_WORKING_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    // delete working directory
    pal_result = pal_fsRmDir(dir_path);
    if (pal_result != PAL_SUCCESS)
    {
        // Any error apart from dir not exist returns error.
        if ((pal_result != PAL_ERR_FS_NO_FILE) && (pal_result != PAL_ERR_FS_NO_PATH))
        {
            tr_err("esfs_reset() - pal_fsRmDir(ESFS_WORKING_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, dir_path);
    if (pal_result != PAL_SUCCESS)
    {

        tr_err("esfs_reset() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(dir_path, "/" ESFS_BACKUP_DIRECTORY, 1 + sizeof(ESFS_BACKUP_DIRECTORY));

    // delete the files in backup dir
    pal_result = pal_fsRmFiles(dir_path);
    // the use case is that esfs folder may not exist
    if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NO_FILE) && (pal_result != PAL_ERR_FS_NO_PATH))
    {
        tr_err("esfs_reset() - pal_fsRmFiles(ESFS_BACKUP_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    pal_result = pal_fsRmDir(dir_path);
    if (pal_result != PAL_SUCCESS)
    {
        // Any error apart from dir not exist returns error.
        if ((pal_result != PAL_ERR_FS_NO_FILE) && (pal_result != PAL_ERR_FS_NO_PATH))
        {
            tr_err("esfs_reset() - pal_fsRmDir(ESFS_BACKUP_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    if (esfs_finalize() != ESFS_SUCCESS)
    {
        tr_err("esfs_reset() - esfs_finalize() failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    if (esfs_init() != ESFS_SUCCESS)
    {
        tr_err("esfs_reset() - esfs_init() failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    return ESFS_SUCCESS;

errorExit:
    return result;
}


esfs_result_e esfs_factory_reset(void) {
    palStatus_t   pal_result = PAL_SUCCESS;
    esfs_result_e result = ESFS_SUCCESS;
    esfs_file_t file_handle = { 0 };
    char working_dir_path[MAX_FULL_PATH_SIZE] = { 0 };
    char full_path_backup_dir[MAX_FULL_PATH_SIZE] = { 0 };
    bool is_single_partition = true;
    
    tr_info("esfs_factory_reset - enter");
    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, full_path_backup_dir);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_factory_reset() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        return ESFS_ERROR;
    }

    strncat(full_path_backup_dir, "/" ESFS_BACKUP_DIRECTORY "/" FACTORY_RESET_DIR, 1 + sizeof(ESFS_BACKUP_DIRECTORY) + 1 + sizeof(FACTORY_RESET_DIR));
    // Create the factory reset subfolder - FR
    pal_result = pal_fsMkDir(full_path_backup_dir);
    if (pal_result != PAL_SUCCESS)
    {
        // Any error apart from file exist returns error.
        if (pal_result != PAL_ERR_FS_NAME_ALREADY_EXIST)
        {
            tr_err("esfs_factory_reset() - pal_fsMkDir(ESFS_BACKUP_DIRECTORY/FACTORY_RESET_DIR) failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    strncat(full_path_backup_dir, "/" FACTORY_RESET_FILE, 1 + sizeof(FACTORY_RESET_FILE));
    // Create the fr_on flag file
    pal_result = pal_fsFopen(full_path_backup_dir, PAL_FS_FLAG_READWRITEEXCLUSIVE, &(file_handle.file));

    // (res == PAL_SUCCESS) : factory reset is called on the first time
    // (res == PAL_ERR_FS_NAME_ALREADY_EXIST) : factory reset is called again after it was failed 
    // on the first time and therefore the file exists
    if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NAME_ALREADY_EXIST))
    {
        tr_err("esfs_factory_reset() - unexpected filesystem behavior pal_fsFopen() failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    // close the file only if we opened it
    if (pal_result == PAL_SUCCESS)
    {
        pal_result = pal_fsFclose(&(file_handle.file));
        if (pal_result != PAL_SUCCESS)
        {
            tr_err("esfs_factory_reset() - unexpected filesystem behavior pal_fsFclose() failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, working_dir_path);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_factory_reset() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Check if there is a single partition by comparing the primary and secondary mount points.
    // This is the only reliable way to do it, since the logic that determines the number of partitions is
    // hidden behind the PAL API.
    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, full_path_backup_dir);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_factory_reset() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }
    is_single_partition = (strcmp(working_dir_path,full_path_backup_dir) == 0);

    strncat(working_dir_path, "/" ESFS_WORKING_DIRECTORY, 1 + sizeof(ESFS_WORKING_DIRECTORY));

    // We can only format the working folder if it is dedicated for exclusive use of esfs and
    // it is not the only partition that exists. The assumption here is that if it is the only partition,
    // then the backup folder is also on that partition. In that case, formatting would remove the backup partition,
    // which we do not want to do!
    if (pal_fsIsPrivatePartition(PAL_FS_PARTITION_PRIMARY) && !is_single_partition)
    {
        pal_result = pal_fsFormat(PAL_FS_PARTITION_PRIMARY);
        if (pal_result != PAL_SUCCESS)
        {
            tr_err("esfs_factory_reset() - pal_fsFormat() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
        pal_result = pal_fsMkDir(working_dir_path);
        if (pal_result != PAL_SUCCESS)
        {
            tr_err("esfs_factory_reset() - pal_fsMkDir(ESFS_WORKING_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }
    else
    {
        // delete the files in working dir
        pal_result = pal_fsRmFiles(working_dir_path);
        // the use case is that esfs folder may not exist
        if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NO_FILE) && (pal_result != PAL_ERR_FS_NO_PATH))
        {
            tr_err("esfs_factory_reset() - pal_fsRmFiles(ESFS_WORKING_DIRECTORY) failed with pal_status = 0x%x", (unsigned int)pal_result);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, full_path_backup_dir);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_factory_reset() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        return ESFS_ERROR;
    }
    strncat(full_path_backup_dir, "/" ESFS_BACKUP_DIRECTORY, 1 + sizeof(ESFS_BACKUP_DIRECTORY));

    pal_result = pal_fsCpFolder(full_path_backup_dir, working_dir_path);

    if ((pal_result != PAL_SUCCESS) && (pal_result != PAL_ERR_FS_NO_FILE))
    {
        tr_err("esfs_factory_reset() - pal_fsCpFolder() from backup to working failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(full_path_backup_dir, "/" FACTORY_RESET_DIR "/" FACTORY_RESET_FILE, 1 + sizeof(FACTORY_RESET_DIR) + 1 + sizeof(FACTORY_RESET_FILE));
    // delete the flag file because factory reset flow ended successfully 
    pal_result = pal_fsUnlink(full_path_backup_dir);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_factory_reset() - pal_fsUnlink(ESFS_BACKUP_DIRECTORY/FACTORY_RESET_DIR/FACTORY_RESET_FILE) failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
     }

    return ESFS_SUCCESS;

errorExit:
    return result;
}

// Internal function to read header information and check its' validity.
// Checks the name given against the name written in the file.
// Checks the version.
// Initializes some fields of file_handle: blob_name_length, esf_mode
// Assumes that the read position is at the start of the file.
// CMAC is calculated.
// Parameters :
// name         [IN]  A pointer to an array of binary data that uniquely identifies the file.
// name_length  [IN]  size in bytes of the name. The minimum is 1 and the maximum is ESFS_MAX_NAME_LENGTH.
// file_handle  [IN]  A pointer to a file handle on which we calculate the position.
// return esf_success - name matches;
//                        ESFS_HASH_CONFLICT - name does not match
//                        ESFS_WRONG_FILE_VERSION - version does not match
//                        ESFS_ERROR - other problem
// On ESFS_SUCCESS or ESFS_HASH_CONFLICT the read position is set after the name.
// On failure the position is undefined.
static esfs_result_e esfs_check_file_validity(const uint8_t* name, size_t name_length, esfs_file_t *file_handle)
{
    esfs_result_e result = ESFS_ERROR;

    // Read the version
    uint16_t version;
    size_t num_bytes;
    result  = esfs_cmac_read(file_handle, &version , sizeof(version), &num_bytes);
    if (result != ESFS_SUCCESS || num_bytes != sizeof(version))
    {
        tr_err("esfs_check_file_validity() - esfs_cmac_read() failed with ESFS result = 0x%x and num_bytes bytes = %zu",
            (unsigned int)result, num_bytes);
        goto errorExit;
    }
    // Check that the files version is the same as the source code version.
    if(version != ESFS_FILE_FORMAT_VERSION)
    {
        tr_err("esfs_check_file_validity() - invalid version: failed with version = %u instead of %u", (unsigned int)version, (unsigned int)ESFS_FILE_FORMAT_VERSION);
        result = ESFS_INVALID_FILE_VERSION;
        goto errorExit;
    }

    // Read the mode
    result = esfs_cmac_read(file_handle, (void *)( &file_handle->esfs_mode ), sizeof(file_handle->esfs_mode), &num_bytes);
    if (result != ESFS_SUCCESS || num_bytes != sizeof(file_handle->esfs_mode))
    {
        tr_err("esfs_check_file_validity() mode -  failed num_bytes bytes = %zu", num_bytes);
        goto errorExit;
    }
    // The mode is not used further in the opening process, so no further checks need be performed as cmac check will detect any
    // tampering.

    // Read the name length
    result = esfs_cmac_read(file_handle, (void *)( &file_handle->blob_name_length ), sizeof(file_handle->blob_name_length), &num_bytes);
    if (result != ESFS_SUCCESS || num_bytes != sizeof(file_handle->blob_name_length))
    {
        tr_err("esfs_check_file_validity() name length- esfs_cmac_read() failed with  result = 0x%x and num_bytes bytes = %zu",
            (unsigned int)result, num_bytes);
        goto errorExit;
    }
    // Check that the name in the file is the same length as the one given. It cannot be greater than ESFS_MAX_NAME_LENGTH
    // because that is checked on entry to the function.
    if (name_length != file_handle->blob_name_length)
    {
        tr_err("esfs_check_file_validity() - name length conflict");
        // The hash of the name conflicts with the hash of another name.
        result = ESFS_HASH_CONFLICT;
        goto errorExit;
    }
    // Check the name chunk by chunk
    for (int i = (int)name_length; i > 0; i -= ESFS_READ_CHUNK_SIZE_IN_BYTES)
    {
        // Read a chunk
        char buffer[ESFS_READ_CHUNK_SIZE_IN_BYTES];
        result = esfs_cmac_read(file_handle, (void *)buffer, (size_t)PAL_MIN(i, ESFS_READ_CHUNK_SIZE_IN_BYTES), &num_bytes);
        if (result != ESFS_SUCCESS || num_bytes == 0)
        {
            tr_err("esfs_check_file_validity() - read name failed with ESFS result = 0x%x and num_bytes bytes = %zu",
                (unsigned int)result, num_bytes);
            goto errorExit;
        }
        // Check that the chunk matches
        //tr_info("Comparing %s (%d bytes) name_length=%d", name, (int )num_bytes,(int )name_length);
        if (memcmp(buffer, name, num_bytes) != 0)
        {
            tr_err("esfs_check_file_validity() - esfs hash conflict : The hash of the name conflicts with the hash of another name");
            // The hash of the name conflicts with the hash of another name.
            result = ESFS_HASH_CONFLICT;
            goto errorExit;
        }
        // Advance past what we just checked.
        name += num_bytes;
    }
    return ESFS_SUCCESS;
errorExit:
    return result;
}

// Internal function to check the name against the name written in the file.
// Assume that the read position is set to before the name length.
// Parameters :
//             fd -      [IN]  A pointer to a file descriptor.
//             file_size [OUT] A pointer to a value into which the file size is returned.
// return esf_success - name matches;
//                        ESFS_HASH_CONFLICT - name does not match ;
//                        ESFS_ERROR - other problem
// On ESFS_SUCCESS or ESFS_HASH_CONFLICT the read position is set after the name.
// On failure the position is undefined.

// Helper function
// Restores current position unless it fails.
// On failure the position is undefined.
static palStatus_t esfs_get_physical_file_size(palFileDescriptor_t* fd, int32_t *file_size)
{
    palStatus_t res;

    // Get current position
    int32_t current_pos;
    off_t pal_offset;

    res = pal_fsFtell(fd, &pal_offset);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_get_physical_file_size() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)res);
        goto errorExit;
    }
    current_pos = (int32_t)pal_offset;

    // Seek to end of file
    res = pal_fsFseek(fd, 0, PAL_FS_OFFSET_SEEKEND);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_get_physical_file_size() - pal_fsFseek() failed with pal_status = 0x%x", (unsigned int)res);
        goto errorExit;
    }
    // Get new position
    res = pal_fsFtell(fd, &pal_offset);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_get_physical_file_size() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)res);
        goto errorExit;
    }
    *file_size = (int32_t)pal_offset;

    // Restore old position
    res = pal_fsFseek(fd, current_pos, PAL_FS_OFFSET_SEEKSET);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_get_physical_file_size() - pal_fsFseek() failed with pal_status = 0x%x", (unsigned int)res);
        goto errorExit;
    }

errorExit:
    return res;
}

// Copy one file to another.
// Parameters :
//             src_file  - [IN] A pointer to a string containing the source file name.
//             src_file  - [IN] A pointer to a string containing the destination file name.
// Return     : ESFS_SUCCESS on success. Error code otherwise
static esfs_result_e esfs_copy_file(const char *src_file, const char *dst_file)
{
    bool is_src_file_opened = false;
    bool is_dst_file_opened = false;
    esfs_file_t file_handle = { 0 };
    esfs_file_t file_handle_copy = { 0 };
    esfs_result_e result = ESFS_ERROR;
    palStatus_t res = PAL_SUCCESS;
    size_t bytes_to_read = ESFS_FILE_COPY_CHUNK_SIZE;
    size_t num_bytes_read = 0;
    size_t num_bytes_write = 0;
    uint8_t buffer[ESFS_FILE_COPY_CHUNK_SIZE] = {0};
    int32_t file_size = 0;
    int32_t copied_bytes = 0;
    // Open src file read only mode
    res = pal_fsFopen(src_file, PAL_FS_FLAG_READONLY, &(file_handle.file));
    if (res != PAL_SUCCESS)
    {
        // File cannot be opened so return an error
        tr_err("esfs_copy_file() - pal_fsFopen() src file failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_NOT_EXISTS;
        goto errorExit;
    }
    is_src_file_opened = true;
    // Open for reading and writing exclusively, If the file already exists, trunced file
    res = pal_fsFopen(dst_file, PAL_FS_FLAG_READWRITETRUNC, &(file_handle_copy.file));
    if (res != PAL_SUCCESS)
    {
        // File cannot be opened so return an error
        tr_err("esfs_copy_file() - pal_fsFopen() dst file failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }
    is_dst_file_opened = true;

    res = esfs_get_physical_file_size(&(file_handle.file), &file_size);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_copy_file() - esfs_get_physical_file_size() failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }
    while (copied_bytes < file_size)
    {
        if (copied_bytes + (int32_t)bytes_to_read > file_size)
        {
            bytes_to_read = (size_t)(file_size - copied_bytes);
        }
        res = pal_fsFread(&(file_handle.file), buffer, bytes_to_read, &num_bytes_read);
        if (res != PAL_SUCCESS)
        {
            tr_err("esfs_copy_file() - pal_fsFread() failed with pal_status = 0x%x", (unsigned int)res);
            result = ESFS_ERROR;
            goto errorExit;
        }

        res = pal_fsFwrite(&(file_handle_copy.file), buffer, bytes_to_read, &num_bytes_write);
        if ((res != PAL_SUCCESS) || (num_bytes_write != bytes_to_read))
        {
            tr_err("esfs_copy_file() - pal_fsFwrite() failed with pal result = 0x%x and num_bytes_write bytes = %zu",
                (unsigned int)res, num_bytes_write);
            result = ESFS_ERROR;
            goto errorExit;
        }

        copied_bytes += (int32_t)bytes_to_read;
    }

    res = pal_fsFclose(&(file_handle.file));
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_copy_file() - pal_fsFclose() for src file failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }
    res = pal_fsFclose(&(file_handle_copy.file));
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_copy_file() - pal_fsFclose() for dst file failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }
    return ESFS_SUCCESS;

errorExit:
    if (is_src_file_opened)
    {
        // we will not delete the src file
        pal_fsFclose(&(file_handle.file));
    }

    if (is_dst_file_opened)
    {
        pal_fsFclose(&(file_handle_copy.file));
        // Clean up if possible. Ignore return value.
        (void)pal_fsUnlink(dst_file);
    }
    return result;
}




// Internal function to create a new file and open it for writing.
// Does not return error if file exists.
// Keep all the conditions that allow the file creation in a single function, esfs_create, while the
// esfs_create_internal will concentrate on file creation mechanics.
// Parameters:
// name          - [IN]    A pointer to an array of binary data that uniquely identifies the file.
// name_length   - [IN]    size in bytes of the name. The minimum is 1 and the maximum is ESFS_MAX_NAME_LENGTH.
// meta_data     - [IN]    A pointer to an array of TLVs structures with meta_data_qty members
// meta_data_qty - [IN]    number of tlvs in the array pointed by meta_data parameter. Minimum is 0 maximum is ESFS_MAX_TYPE_LENGTH_VALUES
// esfs_mode     - [IN]    a bit map combination of values from enum EsfsMode.
// file_handle   - [IN/OUT]  Pointer to the handle data structure into which to write the new handle.
// returns ESFS_SUCCESS The file handle can be used in other esfs functions. It must be closed to release it.
//          ESFS_ERROR - other problem
static esfs_result_e esfs_create_internal( const uint8_t *name,
                                           size_t name_length,
                                           const esfs_tlv_item_t *meta_data,
                                           size_t meta_data_qty,
                                           uint16_t esfs_mode,
                                           esfs_file_t *file_handle,
                                           const char* full_path_to_create
                                        )
{
    esfs_result_e result = ESFS_ERROR;

    int32_t position = 0;
    size_t i;
    uint16_t file_created = 0;
    uint16_t cmac_created = 0;
    uint16_t u16 = ESFS_FILE_FORMAT_VERSION;
    off_t pal_offset;

    // Create the file.
    // Note that we always overwrite any previous file.
    palStatus_t res = pal_fsFopen(full_path_to_create, PAL_FS_FLAG_READWRITETRUNC, &file_handle->file);
    if(res != PAL_SUCCESS)
    {
        // more informative message will be written after hash conflict will be implemented
        tr_err("esfs_create_internal() - pal_fsFopen() failed with status 0x%x", (unsigned int)res);
        goto errorExit;
    }
    file_created = 1;

    if(esfs_cmac_start(file_handle) != ESFS_SUCCESS)
    {
        goto errorExit;
    }
    cmac_created = 1;

    // Write the version
    if(esfs_fwrite_and_calc_cmac(&u16, sizeof(u16), file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for esfs version failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Write the mode
    if(esfs_fwrite_and_calc_cmac(&esfs_mode, sizeof(esfs_mode), file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for esfs_mode failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Header
    // Write the name length
    u16 = (uint16_t)name_length;
    if(esfs_fwrite_and_calc_cmac(&u16, sizeof(u16), file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for name_length failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Write the name
    if(esfs_fwrite_and_calc_cmac(name, name_length, file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for name failed.");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Write the AES nonce, whether the file is encrypted or not. This ensures that the file format is the same
    // whether encrypted or not.
    if ((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        if(esfs_fwrite_and_calc_cmac((void *)(file_handle->nonce), ESFS_AES_NONCE_SIZE_BYTES, file_handle) != ESFS_SUCCESS)
        {
            tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for AES nonce failed");
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    // Write the Metadata header
    // Write the number of items of meta data
    u16 = (uint16_t)meta_data_qty;
    if(esfs_fwrite_and_calc_cmac(&u16,sizeof(u16), file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for number of items of meta data failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // If there is meta data
    if(meta_data_qty != 0)
    {
        res = pal_fsFtell(&file_handle->file, &pal_offset);
        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_create_internal() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)res);
            result = ESFS_ERROR;
            goto errorExit;
        }
        position = (int32_t)pal_offset;

        position += (int32_t)(sizeof(file_handle->tlv_properties.tlv_items[0]) * meta_data_qty);
        for(i = 0; i < meta_data_qty; i++ )
        {
            file_handle->tlv_properties.tlv_items[i].type = meta_data[i].type;
            file_handle->tlv_properties.tlv_items[i].length_in_bytes = meta_data[i].length_in_bytes;
            file_handle->tlv_properties.tlv_items[i].position = (uint16_t)position;
            // Increment position for next iteration
            position += meta_data[i].length_in_bytes;
        }

        // Write the metadata items
        result = esfs_fwrite_and_calc_cmac(&file_handle->tlv_properties.tlv_items[0], sizeof(file_handle->tlv_properties.tlv_items[0])*meta_data_qty, file_handle);
        if(result != ESFS_SUCCESS)
        {
            tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for meta data items failed with esfs result = 0x%x", result);
            result = ESFS_ERROR;
            goto errorExit;
        }

        // Set the number_of_items field here since it is in use later in this function
        // when we calculate the file header size
        file_handle->tlv_properties.number_of_items = (uint16_t)meta_data_qty;

        // Write the Metadata data values
        // If encrypted esfs is requested (by the esfs_mode argument), then this part should be encrypted
        for(i = 0; i < meta_data_qty; i++ )
        {
            if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
            {
                result = esfs_encrypt_fwrite_and_calc_cmac(meta_data[i].value, meta_data[i].length_in_bytes, file_handle);
            }
            else
            {
                result = esfs_fwrite_and_calc_cmac(meta_data[i].value, meta_data[i].length_in_bytes, file_handle);
            }

            if(result != ESFS_SUCCESS)
            {
                tr_err("esfs_create_internal() - esfs_fwrite_and_calc_cmac() for meta data item values failed with esfs result = 0x%x", result);
                result = ESFS_ERROR;
                goto errorExit;
            }
        }
    }

    file_handle->file_flag = ESFS_WRITE;

    return ESFS_SUCCESS;

errorExit:

    if(file_created)
    {
        pal_fsFclose(&file_handle->file);
        // Clean up if possible. Ignore return value.
        (void)pal_fsUnlink(full_path_to_create);
    }
    if(cmac_created)
    {
        uint8_t key[ESFS_CMAC_SIZE_IN_BYTES];
        // Clean up cmac. Ignore error.
        (void)esfs_cmac_finish(file_handle, &key[0]);
    }

    return result;
}

//      ---------------------------------------------------------------
//                              API Functions
//      ---------------------------------------------------------------


esfs_result_e esfs_create(const uint8_t *name, size_t name_length, const esfs_tlv_item_t *meta_data, size_t meta_data_qty, uint16_t esfs_mode, esfs_file_t *file_handle)
{

    palStatus_t   res    = PAL_SUCCESS;
    esfs_result_e result = ESFS_ERROR;

    bool is_aes_ctx_created = false;


    // Verify that the structure is always packed to six bytes, since we read and write it as a whole.
    PAL_ASSERT_STATIC(sizeof(esfs_tlvItem_t) == 6);

    // Verify that the array is always packed without padding, since we read and write it as a whole.
    PAL_ASSERT_STATIC(sizeof(esfs_tlvItem_t[ESFS_MAX_TYPE_LENGTH_VALUES]) == ESFS_MAX_TYPE_LENGTH_VALUES * sizeof(esfs_tlvItem_t));

    tr_info("esfs_create - enter");

    // Check parameters
    if (!file_handle || !name || name_length == 0 || name_length > ESFS_MAX_NAME_LENGTH || meta_data_qty > ESFS_MAX_TYPE_LENGTH_VALUES)
    {
        tr_err("esfs_create() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    // Check the metadata parameter
    for(size_t meta_data_index = 0; meta_data_index < meta_data_qty; meta_data_index++ )
    {
        if ((!meta_data[meta_data_index].value) || (meta_data[meta_data_index].length_in_bytes == 0))
        {
            tr_err("esfs_create() failed with bad parameters for metadata");
            result = ESFS_INVALID_PARAMETER;
            goto errorExit;
        }
    }

    // If esfs is in encryption mode, make the required initializations
    if((esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        // ** Create AES context for AES encryption
        res = pal_initAes( &(file_handle->aes_ctx) );

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_create() - pal_initAes() failed with pal status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }

        is_aes_ctx_created = true;

        // ** Get AES key from PAL
        // Note: On each call, PAL should return the same 128 bits key
        uint8_t aes_key[ESFS_AES_KEY_SIZE_BYTES]; // For AES encryption
        res = pal_osGetDeviceKey(palOsStorageEncryptionKey128Bit, aes_key, ESFS_AES_KEY_SIZE_BYTES);

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_create() - pal_osGetDeviceKey() failed with pal status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }

        // ** Assign generated AES key to AES context
        res = pal_setAesKey( file_handle->aes_ctx,
                             aes_key,
                             ESFS_AES_KEY_SIZE_BITS,
                             PAL_KEY_TARGET_ENCRYPTION
                           );

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_create() - pal_setAesKey() failed with pal status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }

        // ** Generate the AES nonce for AES usage
        res = pal_osRandomBuffer(file_handle->nonce, ESFS_AES_NONCE_SIZE_BYTES);

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_create() - pal_osRandomBuffer() failed with pal status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }
    }

    // We set the blob_name_length field here because it is in use later in this function when we calculate the file header size.
    // Since this field is also used to check the file handle validity [ esfs_validate() ] we set it to zero on an error exit.
    file_handle->blob_name_length = (uint16_t)name_length;

    file_handle->esfs_mode = esfs_mode;

    file_handle->file_invalid = 0;

    file_handle->tlv_properties.number_of_items = 0;

    // Indicate that there is not a signature context yet.
    file_handle->signature_ctx = 0;

    file_handle->data_size = 0;

    if (esfs_get_name_from_blob(name, (uint32_t)name_length, file_handle->short_file_name, ESFS_FILE_NAME_LENGTH) != ESFS_SUCCESS)
    {
        tr_err("esfs_create() - esfs_get_name_from_blob() failed");
        goto errorExit;
    }

    // Put working file name in file_full_path
    char file_full_path[MAX_FULL_PATH_SIZE];
    res = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, file_full_path);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_create() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }
    strncat(file_full_path, "/" ESFS_WORKING_DIRECTORY "/", 1 + sizeof(ESFS_WORKING_DIRECTORY) + 1);
    strncat(file_full_path, file_handle->short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);


    // Check if the file exists in the working directory (not acceptable)
    // Note that this is just a check. We will only actually open the file later (in esfs_create_internal()).
    res = pal_fsFopen(file_full_path, PAL_FS_FLAG_READONLY, &file_handle->file);
    if (res == PAL_SUCCESS)
    {
        result = ESFS_EXISTS;
        file_handle->esfs_mode = 0;
        // result can be ESFS_HASH_CONFLICT or ESFS_WRONG_FILE_VERSION
        // Check if there is a different name in the file
        // Check that the name written inside the file is the same as that given. If not
        // you should choose a different name.
        esfs_result_e check_result = esfs_check_file_validity(name, name_length, file_handle);
        if (check_result == ESFS_HASH_CONFLICT || check_result == ESFS_INVALID_FILE_VERSION)
        {
            result = check_result;
        }
        pal_fsFclose(&file_handle->file);
        tr_err("esfs_create() - pal_fsFopen() for working dir file failed");
        goto errorExit;
    }

    // If factory reset file then we make some checks
    if (esfs_mode & (uint16_t)ESFS_FACTORY_VAL)
    {
        // Put backup folder name in file_full_path
        res = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, file_full_path);
        if (res != PAL_SUCCESS)
        {
            tr_err("esfs_create() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)res);
            result = ESFS_ERROR;
            goto errorExit;
        }
        strncat(file_full_path, "/" ESFS_BACKUP_DIRECTORY, 1 + sizeof(ESFS_BACKUP_DIRECTORY));

        // Create the esfs subfolder for backup
        res = pal_fsMkDir(file_full_path);
        if (res != PAL_SUCCESS)
        {
            // Any error apart from file exist returns error.
            if (res != PAL_ERR_FS_NAME_ALREADY_EXIST)
            {
                tr_err("esfs_create() - pal_fsMkDir() for backup dir failed with pal status 0x%x", (unsigned int)res);
                goto errorExit;
            }
        }

        // Put backup file name in file_full_path
        strcat(file_full_path, "/");
        strncat(file_full_path, file_handle->short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

        // Check if the file exists in esfs backup directory (acceptable unless there is a hash conflict for the name)
        res = pal_fsFopen(file_full_path, PAL_FS_FLAG_READONLY, &file_handle->file);
        if (res == PAL_SUCCESS)
        {
            file_handle->esfs_mode = 0;
            // result can be ESFS_HASH_CONFLICT or ESFS_WRONG_FILE_VERSION
            // Check if there is a different name in the file
            // Check that the name written inside the file is the same as that given. If not
            // you should choose a different name.
            esfs_result_e check_result = esfs_check_file_validity(name, name_length, file_handle);

            // Close the file.
            pal_fsFclose(&file_handle->file);

            if (check_result == ESFS_HASH_CONFLICT || check_result == ESFS_INVALID_FILE_VERSION)
            {
                tr_err("esfs_create() - esfs_check_file_validity() failed with status 0x%x", check_result);
                result = check_result;
                goto errorExit;
            }
            // It is OK for it to exist, so continue.
        }
    }

    // Now we actually create the new file.
    // file_full_path contains the correct location (working/backup)
    result = esfs_create_internal(
                                    name,
                                    name_length,
                                    meta_data,
                                    meta_data_qty,
                                    esfs_mode,
                                    file_handle,
                                    // Working or backup
                                    file_full_path
                                );
    if(result != ESFS_SUCCESS)
    {
        goto errorExit;
    }

    return ESFS_SUCCESS;

errorExit:

    // Invalidate blob_name_length filed since it is used to check the file handle validity  [ esfs_validate() ]
    if(file_handle != NULL)
    {
        file_handle->blob_name_length = 0;
    }

    if(is_aes_ctx_created)
    {
        pal_freeAes( &(file_handle->aes_ctx) );
    }
    return result;
}

esfs_result_e esfs_open(const uint8_t *name, size_t name_length, uint16_t *esfs_mode, esfs_file_t *file_handle)
{
    esfs_result_e result = ESFS_ERROR;
    uint16_t file_opened = 0;
    uint16_t cmac_created = 0;
    bool is_aes_ctx_created = false;
    palStatus_t res = PAL_SUCCESS;

    tr_info("esfs_open - enter");
    // Check parameters
    if(!file_handle || !name || name_length == 0 || name_length > ESFS_MAX_NAME_LENGTH)
    {
        tr_err("esfs_open() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    char working_dir_path[MAX_FULL_PATH_SIZE];
    res = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, working_dir_path);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_open() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)res);
        return ESFS_ERROR;
    }

    strncat(working_dir_path, "/" ESFS_WORKING_DIRECTORY "/", 1 + sizeof(ESFS_WORKING_DIRECTORY) + 1);

    // This is used to esfs_validate the file handle so we set it to zero here and only when open
    // succeeds to the real value.
    file_handle->blob_name_length = 0;

    file_handle->file_invalid = 0;

    memset(&file_handle->cmac[0], 0, sizeof(file_handle->cmac));

    if(esfs_get_name_from_blob(name, (uint32_t)name_length, file_handle->short_file_name, ESFS_FILE_NAME_LENGTH) != ESFS_SUCCESS)
    {
        tr_err("esfs_open() - esfs_get_name_from_blob() failed");
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(working_dir_path, file_handle->short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

   // Open the file read only
    res = pal_fsFopen(working_dir_path, PAL_FS_FLAG_READONLY, &file_handle->file);
    if(res != PAL_SUCCESS)
    {
        // tr_err("esfs_open() - pal_fsFopen() for working dir file failed with pal_status = 0x%x", (unsigned int)res);
        // File cannot be opened so return an error
        result = ESFS_NOT_EXISTS;
        goto errorExit;
    }

     file_opened = 1;

     if(esfs_cmac_start(file_handle) != ESFS_SUCCESS)
     {
         goto errorExit;
     }
     cmac_created = 1;

    // Check that the name written inside the file is the same as that given
    // Note: After this call, the read position will be set to the point after the "Name Blob"
    result = esfs_check_file_validity(name, name_length, file_handle);
    if(result != ESFS_SUCCESS)
    {
        // the requested file not exists, but exists file with the same short name
        if (result == ESFS_HASH_CONFLICT)
        {
             result = ESFS_NOT_EXISTS;  		
        }					    
        tr_err("esfs_open() - esfs_check_file_validity() failed with status = 0x%x", result);
        // File cannot be opened so return an error
        goto errorExit;
    }

    if (esfs_mode)
    {
        *esfs_mode = file_handle->esfs_mode;    // file_handle->esfs_mode was set by esfs_check_file_validity()
    }

    // If esfs is in encryption mode, make the required initializations
    if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        // ** Create AES context for AES decryption
        res = pal_initAes( &(file_handle->aes_ctx) );

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_open() - pal_initAes() failed with status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }

        is_aes_ctx_created = true;

        // ** Get AES key from PAL
        // Note: On each call, PAL should return the same 128 bits key
        uint8_t aes_key[ESFS_AES_KEY_SIZE_BYTES];
        res = pal_osGetDeviceKey(palOsStorageEncryptionKey128Bit, aes_key, ESFS_AES_KEY_SIZE_BYTES);

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_open() - pal_osGetDeviceKey() failed with status 0x%x", (unsigned int)res);
            result = ESFS_ERROR ;
            goto errorExit;
        }

        // ** Assign generated AES key to AES context
        res = pal_setAesKey( file_handle->aes_ctx,
                             aes_key,
                             ESFS_AES_KEY_SIZE_BITS,
                             PAL_KEY_TARGET_ENCRYPTION
                           );

        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_open() - pal_setAesKey() failed with status 0x%x", (unsigned int)res);
            result = ESFS_ERROR;
            goto errorExit;
        }

    }

    size_t num_bytes;

    // ** Read the AES nonce into file_handle->nonce
    if ((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        result = esfs_cmac_read(file_handle, &file_handle->nonce[0], ESFS_AES_NONCE_SIZE_BYTES, &num_bytes);
        if((result != ESFS_SUCCESS) || (num_bytes != ESFS_AES_NONCE_SIZE_BYTES))
        {
            tr_err("esfs_open() - esfs_cmac_read() (AES nonce) failed with ESFS result = 0x%x and num_bytes bytes = %zu",
                (unsigned int)result, num_bytes);
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    file_handle->tlv_properties.number_of_items = 0;

    // Read the number of items of meta data
    uint16_t meta_data_qty;
    result = esfs_cmac_read(file_handle, (void *)( &meta_data_qty ), sizeof(meta_data_qty), &num_bytes);
    if(result != ESFS_SUCCESS || num_bytes != sizeof(meta_data_qty) || meta_data_qty > ESFS_MAX_TYPE_LENGTH_VALUES)
    {
        tr_err("esfs_open() - esfs_cmac_read() (number of items of meta data) failed with ESFS result = 0x%x and num_bytes bytes = %zu",
            (unsigned int)result, num_bytes);
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Read the metadata properties if there are any
    if(meta_data_qty != 0)
    {
        result = esfs_cmac_read( file_handle,
                           (void *) ( &(file_handle->tlv_properties.tlv_items[0]) ),
                           (sizeof(file_handle->tlv_properties.tlv_items[0]) * meta_data_qty),
                           &num_bytes
                         );

        if(result != ESFS_SUCCESS || num_bytes != sizeof(file_handle->tlv_properties.tlv_items[0])*meta_data_qty)
        {
            tr_err("esfs_open() - esfs_cmac_read() (metadata properties) failed with ESFS result = 0x%x and num_bytes bytes = %zu",
                (unsigned int)result, num_bytes);
            goto errorExit;
        }

        // Skip to the start of the data by calculating the last metadata position plus its length
        esfs_tlvItem_t *ptypeLengthValueItem = &file_handle->tlv_properties.tlv_items[meta_data_qty - 1];

        if(esfs_cmac_skip_to(file_handle, ptypeLengthValueItem->position + ptypeLengthValueItem->length_in_bytes) != ESFS_SUCCESS)
        {
            tr_err("esfs_open() - esfs_cmac_skip_to() failed.");
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    file_handle->tlv_properties.number_of_items = meta_data_qty;

    // We are at the start of the data section
    file_handle->current_read_pos = 0;

    // Get current position
    int32_t current_pos;
    off_t pal_offset;
    res = pal_fsFtell(&file_handle->file, &pal_offset);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_open() - pal_fsFtell() failed with pal_status = 0x%x", (unsigned int)res);
        goto errorExit;
    }
    current_pos = (int32_t)pal_offset;

    // get the whole file size and store it in the handle
    res = esfs_get_physical_file_size(&file_handle->file, &file_handle->file_size);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_open() - esfs_open() failed with status 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Skip to the end of the file while calculating the cmac
    if(esfs_cmac_skip_to(file_handle, file_handle->file_size - ESFS_CMAC_SIZE_IN_BYTES) != ESFS_SUCCESS)
    {
        tr_err("esfs_open() - esfs_cmac_skip_to() failed.");
        result = ESFS_ERROR;
        goto errorExit;
    }

    // Terminate cmac calculation and get it.
    unsigned char cmac[ESFS_CMAC_SIZE_IN_BYTES];
    if(esfs_cmac_finish(file_handle, &cmac[0]) != ESFS_SUCCESS)
    {
        tr_err("esfs_open() - esfs_finish_cmac() failed");
        goto errorExit;
    }
    cmac_created = 0;

    // save the CMAC in the file descriptor. We will use this to check that the file has not
    // changed when esfs_read() or read_meta_data() is called.
    memcpy(&file_handle->cmac[0],&cmac[0],sizeof(file_handle->cmac));

    // Check the cmac and set the file position to the start of the data
    if(esfs_cmac_check_and_restore(file_handle, &cmac[0], current_pos) != ESFS_SUCCESS)
    {
        tr_err("esfs_open() - cmac that we read from the file does not match the one that we calculated");
        result = ESFS_CMAC_DOES_NOT_MATCH;
        goto errorExit;
    }

    // Calculate the size of the data only, by getting the file size and deducting the header and cmac
    file_handle->data_size = (size_t)file_handle->file_size - esfs_file_header_size(file_handle);

    // We deduct the cmac bytes at the end of the file since they are not part of the data
    file_handle->data_size -= ESFS_CMAC_SIZE_IN_BYTES;

    file_handle->file_flag = ESFS_READ;
    file_handle->blob_name_length = (uint16_t)name_length;

    return ESFS_SUCCESS;

errorExit:
    if(file_opened)
    {
        pal_fsFclose(&file_handle->file);
    }
    if(is_aes_ctx_created)
    {
        pal_freeAes( &(file_handle->aes_ctx) );
    }
    if(cmac_created)
    {
        // Clean up cmac. Ignore error.
        (void)esfs_cmac_finish(file_handle, &cmac[0]);
    }

    return result;
}

esfs_result_e esfs_write(esfs_file_t *file_handle, const void *buffer, size_t bytes_to_write)
{
    esfs_result_e result = ESFS_ERROR;

    tr_info("esfs_write - enter");
    if((esfs_validate(file_handle) != ESFS_SUCCESS) || (!buffer) || (bytes_to_write == 0))
    {
        tr_err("esfs_write() failed with bad parameters");
        return ESFS_INVALID_PARAMETER;
    }

    if(file_handle->file_flag == ESFS_READ)
    {
        tr_err("esfs_write() write failed - file is opened for read only");
        result = ESFS_FILE_OPEN_FOR_READ;
        goto errorExit;
    }
    else
    {
        // Write data
        // If encrypted esfs is requested (file_handle->esfs_mode), then this part should be encrypted

        // The data should be encrypted if the encrypted esfs is requested by the esfs_mode argument
        if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
        {
            result = esfs_encrypt_fwrite_and_calc_cmac(buffer, bytes_to_write, file_handle);
        }
        else
        {
            result = esfs_fwrite_and_calc_cmac(buffer, bytes_to_write, file_handle);
        }

        if(result != ESFS_SUCCESS)
        {
            tr_err("esfs_write() - esfs_fwrite_and_calc_cmac()/esfs_encrypt_fwrite_and_calc_cmac() for data failed with esfs result = 0x%x", result);
            // Since the write failed, we cannot be sure of the state of the file, so we mark it as invalid.
            file_handle->file_invalid = 1;
            result = ESFS_ERROR;
            goto errorExit;
        }
    }

    file_handle->data_size += bytes_to_write;

    return ESFS_SUCCESS;

errorExit:
    return result;
}

esfs_result_e esfs_read(esfs_file_t *file_handle, void *buffer, size_t bytes_to_read, size_t *read_bytes)
{
    esfs_result_e result = ESFS_ERROR;
    uint16_t cmac_created = 0;
    size_t remaining_bytes = 0;
    palStatus_t res = PAL_SUCCESS;

    tr_info("esfs_read - enter");
    if(esfs_validate(file_handle) != ESFS_SUCCESS || read_bytes == NULL || !buffer)
    {
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    if(file_handle->file_flag != ESFS_READ)
    {
        result = ESFS_FILE_OPEN_FOR_WRITE;
        goto errorExit;
    }
    // Save file position
    int32_t position;
    off_t pal_offset;
    res = pal_fsFtell(&file_handle->file, &pal_offset);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_read() - pal_fsFtell() failed with pal status 0x%x", (unsigned int)res);
        goto errorExit;
    }
    position = (int32_t)pal_offset;

    // Limit how many bytes we can actually read depending on the size of the data section.
    remaining_bytes = file_handle->data_size - (size_t)file_handle->current_read_pos;
    bytes_to_read = PAL_MIN(remaining_bytes, bytes_to_read);

    if(esfs_cmac_start(file_handle) != ESFS_SUCCESS)
    {
        goto errorExit;
    }
    cmac_created = 1;

    if(esfs_cmac_skip_to(file_handle, position) != ESFS_SUCCESS)
    {
        goto errorExit;
    }

    // Read data
    // If required according to esfs_mode, the read data will be decrypted
    size_t num_bytes;
    if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        if(esfs_read_and_decrypt(file_handle, buffer, bytes_to_read, &num_bytes) != ESFS_SUCCESS)
        {
            goto errorExit;
        }
    }
    else
    {
        if(esfs_cmac_read(file_handle, buffer, bytes_to_read, &num_bytes ) != ESFS_SUCCESS)
        {
            goto errorExit;
        }
    }

    *read_bytes = num_bytes;

    if(esfs_cmac_skip_to(file_handle ,file_handle->file_size - ESFS_CMAC_SIZE_IN_BYTES) != ESFS_SUCCESS)
    {
        goto errorExit;
    }

    unsigned char cmac[ESFS_CMAC_SIZE_IN_BYTES];
    if(esfs_cmac_finish(file_handle, &cmac[0]) != ESFS_SUCCESS)
    {
        tr_err("esfs_read() - esfs_finish_cmac() failed");
        goto errorExit;
    }
    cmac_created = 0;

    // Check the cmac and set to the byte after the end of the data being read.
    if(esfs_cmac_check_and_restore(file_handle, &cmac[0], position + (int32_t)num_bytes) != ESFS_SUCCESS)
    {
        tr_err("esfs_read() - cmac that we read from the file does not match the one that we calculated");
        result = ESFS_CMAC_DOES_NOT_MATCH;
        goto errorExit;
    }

    // Update the current position
    file_handle->current_read_pos += (long)num_bytes;

    return ESFS_SUCCESS;

errorExit:
    tr_err("esfs_read errorExit result=0x%x", result);
    if(cmac_created)
    {
        // Clean up cmac. Ignore error and resulting cmac.
        (void)esfs_cmac_finish(file_handle, &cmac[0]);
    }

    return result;
}

esfs_result_e esfs_seek(esfs_file_t *file_handle, int32_t offset, esfs_seek_origin_e whence, uint32_t *position)
{
    esfs_result_e result = ESFS_ERROR;
    palStatus_t res = PAL_SUCCESS;
    off_t pal_offset;

    tr_info("esfs_seek - enter");
    if(esfs_validate(file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_seek() failed with bad parameters");
        return ESFS_INVALID_PARAMETER;
    }

    if(file_handle->file_flag != ESFS_READ)
    {
        tr_err("esfs_seek() seek failed - file is opened for write only");
        result = ESFS_FILE_OPEN_FOR_WRITE;
        goto errorExit;
    }
    pal_fsOffset_t pal_whence;
    // ESFS whence enum values are in sync with those of pal
    if(whence == ESFS_SEEK_SET)
    {
        if(offset > (int32_t)file_handle->data_size || offset < 0)
        {
            tr_err("esfs_seek() failed with bad parameters in offset calculation : ESFS_SEEK_SET");
            result = ESFS_INVALID_PARAMETER;
            goto errorExit;
        }
        // Add the offset to the start of the data
        offset += (int32_t)esfs_file_header_size(file_handle);
        pal_whence = PAL_FS_OFFSET_SEEKSET;
    }
    else if(whence == ESFS_SEEK_END)
    {
        if(offset < -(int32_t)file_handle->data_size || offset > 0)
        {
            tr_err("esfs_seek() failed with bad parameters in offset calculation : ESFS_SEEK_END");
            result = ESFS_INVALID_PARAMETER;
            goto errorExit;
        }
        // Deduct the cmac size from the offset because it is located after the data section.
        offset -= ESFS_CMAC_SIZE_IN_BYTES;
        pal_whence = PAL_FS_OFFSET_SEEKEND;
    }
    else if(whence == ESFS_SEEK_CUR)
    {
        if(offset + file_handle->current_read_pos > (int32_t)file_handle->data_size || offset + (int32_t)file_handle->current_read_pos < 0)
        {
            tr_err("esfs_seek() failed with bad parameters in offset calculation : ESFS_SEEK_CUR");
            result = ESFS_INVALID_PARAMETER;
            goto errorExit;
        }
        pal_whence = PAL_FS_OFFSET_SEEKCUR;
    }
    else
    {
        tr_err("esfs_seek() failed with bad parameters - wrong whence");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }
    res = pal_fsFseek(&file_handle->file, offset, pal_whence);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_seek() - pal_fsFseek() failed with pal status 0x%x", (unsigned int)res);
        goto errorExit;
    }
    // Get current position if position is not NULL
    if(position)
    {
        res = pal_fsFtell(&file_handle->file, &pal_offset);
        if(res != PAL_SUCCESS)
        {
            tr_err("esfs_seek() - pal_fsFtell() failed with pal status 0x%x", (unsigned int)res);
            goto errorExit;
        }
        *position = (uint32_t)pal_offset;

        // Ignore the file header data
        *position -= (uint32_t)esfs_file_header_size(file_handle);

        // Update the current position
        file_handle->current_read_pos = *position;
    }

    return ESFS_SUCCESS;

errorExit:
    return result;
}


esfs_result_e esfs_file_size(esfs_file_t *file_handle, size_t *size_in_bytes)
{
    esfs_result_e result = ESFS_ERROR;

    tr_info("esfs_file_size - enter");
    if((esfs_validate(file_handle) != ESFS_SUCCESS) || (!size_in_bytes))
    {
        tr_err("esfs_file_size() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    *size_in_bytes = file_handle->data_size;

    return ESFS_SUCCESS;

errorExit:
    return result;
}

esfs_result_e esfs_close(esfs_file_t *file_handle)
{
    uint16_t failed_to_write_CMAC = 0;
    uint16_t file_esfs_mode = 0;
    esfs_file_flag_e esfs_file_flag;
    char esfs_short_file_name[ESFS_QUALIFIED_FILE_NAME_LENGTH] = {0};
    esfs_result_e result = ESFS_ERROR;
    char full_path_working_dir[MAX_FULL_PATH_SIZE];
    palStatus_t res = PAL_SUCCESS;

    tr_info("esfs_close - enter");
    if(esfs_validate(file_handle) != ESFS_SUCCESS)
    {
        tr_err("esfs_close() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    res = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, full_path_working_dir);
    if (res != PAL_SUCCESS)
    {
        tr_err("esfs_close() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)res);
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(full_path_working_dir, "/" ESFS_WORKING_DIRECTORY "/", 1 + sizeof(ESFS_WORKING_DIRECTORY) + 1);


    // Close AES context if needed
    if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        pal_freeAes( &(file_handle->aes_ctx) );
    }
 
    esfs_file_flag = file_handle->file_flag;
    file_esfs_mode = file_handle->esfs_mode;
    strncpy(esfs_short_file_name, file_handle->short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

    if(file_handle->file_flag == ESFS_WRITE)
    {
        unsigned char cmac[ESFS_CMAC_SIZE_IN_BYTES];
        // Finish signature calculation
        if(esfs_cmac_finish(file_handle, &cmac[0]) != ESFS_SUCCESS)
        {
            tr_err("esfs_close() - esfs_cmac_finish() failed");
            goto errorExit;
        }
        // Write signature
        size_t bytes_written;
        res = pal_fsFwrite(&file_handle->file, &cmac[0], sizeof(cmac), &bytes_written);
        if(res != PAL_SUCCESS || sizeof(cmac) != bytes_written)
        {
            tr_err("esfs_close() - pal_fsFwrite() (signature) failed with pal result = 0x%x and bytes_written bytes = %zu",
                (unsigned int)res, bytes_written);
            // mark the file invalid on a failed write
            file_handle->file_invalid = 1;
            // Continue so that we delete the file, but we should return failure later
            failed_to_write_CMAC = 1;
        }
    }

    res = pal_fsFclose(&file_handle->file);
    if(res == PAL_SUCCESS)
    {
        // Remove a file that is invalid. It may have become invalid due to a failed write.
        if(file_handle->file_invalid)
        {
            strncat(full_path_working_dir,file_handle->short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

            res = pal_fsUnlink(full_path_working_dir);
            if(res != PAL_SUCCESS)
            {
                tr_err("esfs_close() - pal_fsUnlink() failed with pal status 0x%x", (unsigned int)res);
                goto errorExit;
            }
        }
    }
    else
    {
        tr_err("esfs_close() - pal_fsFclose() failed with pal status 0x%x", (unsigned int)res);
        goto errorExit;
    }

    if(failed_to_write_CMAC)
    {
        goto errorExit;
    }


    if ((file_esfs_mode & ESFS_FACTORY_VAL) && (esfs_file_flag == ESFS_WRITE) && !(file_handle->file_invalid))
    {
        char full_path_backup_dir[MAX_FULL_PATH_SIZE] = { 0 };

        res = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, full_path_backup_dir);
        if (res != PAL_SUCCESS)
        {
            tr_err("esfs_close() - pal_fsGetMountPoint() for backup directory failed with pal_status = 0x%x", (unsigned int)res);
            result = ESFS_ERROR;
            goto errorExit;
        }

        strncat(full_path_backup_dir, "/" ESFS_BACKUP_DIRECTORY "/", 1 + sizeof(ESFS_BACKUP_DIRECTORY) + 1);

        strncat(full_path_working_dir, esfs_short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH -1);
        strncat(full_path_backup_dir, esfs_short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

        if (esfs_copy_file(full_path_backup_dir, full_path_working_dir) != ESFS_SUCCESS)
        {
            tr_err("esfs_close() - esfs_copy_file() failed");
            goto errorExit;
        }
    }

    return ESFS_SUCCESS;
errorExit:
    return result;
}

esfs_result_e esfs_delete(const uint8_t *name, size_t name_length)
{

    palStatus_t pal_result = PAL_SUCCESS;
    char working_dir_path[MAX_FULL_PATH_SIZE] = { 0 };
    char short_file_name[ESFS_QUALIFIED_FILE_NAME_LENGTH];
    esfs_result_e result = ESFS_ERROR;

    tr_info("esfs_delete - enter");
    // Check parameters
    if(!name || name_length == 0)
    {
        tr_err("esfs_delete() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }
    if(esfs_get_name_from_blob(name, (uint32_t)name_length, short_file_name, ESFS_FILE_NAME_LENGTH ) != ESFS_SUCCESS)
    {
        tr_err("esfs_delete() - esfs_get_name_from_blob() failed");
        goto errorExit;
    }
    tr_info("esfs_delete %s", short_file_name);

    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, working_dir_path);
    if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_delete() - pal_fsGetMountPoint() for working directory failed with pal_status = 0x%x", (unsigned int)pal_result);
        result = ESFS_ERROR;
        goto errorExit;
    }

    strncat(working_dir_path, "/" ESFS_WORKING_DIRECTORY "/", 1 + sizeof(ESFS_WORKING_DIRECTORY) + 1);

    // We do not verify that name is the actual name in the file because currently we do not allow the situation of hash
    // clash to arise.

    strncat(working_dir_path,short_file_name, ESFS_QUALIFIED_FILE_NAME_LENGTH - 1);

    tr_info("esfs_delete %s", working_dir_path);
    pal_result = pal_fsUnlink(working_dir_path);

    if ((pal_result == PAL_ERR_FS_NO_FILE) || (pal_result == PAL_ERR_FS_NO_PATH))
    {
        tr_err("esfs_delete() - pal_fsUnlink() failed with pal status 0x%x", (unsigned int)pal_result);
        result = ESFS_NOT_EXISTS;
        goto errorExit;
    }
    else if (pal_result != PAL_SUCCESS)
    {
        tr_err("esfs_delete() - pal_fsUnlink() failed with pal status 0x%x", (unsigned int)pal_result);
        goto errorExit;
    }

    return ESFS_SUCCESS;
errorExit:
    return result;
}

esfs_result_e esfs_get_meta_data_properties(esfs_file_t *file_handle, esfs_tlv_properties_t **meta_data_properties)
{
    esfs_result_e result = ESFS_ERROR;
    tr_info("esfs_get_meta_data_properties - enter");
    if((esfs_validate(file_handle) != ESFS_SUCCESS) || (!meta_data_properties))
    {
        tr_err("esfs_get_meta_data_properties() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    if (file_handle->file_flag != ESFS_READ)
    {
        tr_err("esfs_get_meta_data_properties() failed - file is opened for write only");
        result = ESFS_FILE_OPEN_FOR_WRITE;
        goto errorExit;
    }

    *meta_data_properties = &file_handle->tlv_properties;
    return ESFS_SUCCESS;
errorExit:
    return result;
}


esfs_result_e esfs_read_meta_data(esfs_file_t *file_handle, uint32_t index, esfs_tlv_item_t *meta_data)
{
    esfs_result_e result = ESFS_ERROR;
    bool is_read_error = false;
    uint16_t cmac_created = 0;
    int32_t offset_to_restore = 0;
    palStatus_t res = PAL_SUCCESS;

    tr_info("esfs_read_meta_data - enter");
    if(esfs_validate(file_handle) != ESFS_SUCCESS || index >= ESFS_MAX_TYPE_LENGTH_VALUES || !meta_data || (file_handle->tlv_properties.tlv_items[index].length_in_bytes == 0))
    {
        tr_err("esfs_read_meta_data() failed with bad parameters");
        result = ESFS_INVALID_PARAMETER;
        goto errorExit;
    }

    if(file_handle->file_flag != ESFS_READ)
    {
        tr_err("esfs_read_meta_data() failed - file is opened for write only");
        result = ESFS_FILE_OPEN_FOR_WRITE;
        goto errorExit;
    }
    // Get current file position
    int32_t current_pos;
    off_t pal_offset;
    res = pal_fsFtell(&file_handle->file, &pal_offset);
    if(res != PAL_SUCCESS)
    {
        tr_err("esfs_read_meta_data() - pal_fsFtell() failed with pal status 0x%x", (unsigned int)res);
        goto errorExit;
    }
    current_pos = (int32_t)pal_offset;

    // Start the cmac calculation and position to the start of the file
    if(esfs_cmac_start(file_handle) != ESFS_SUCCESS)
    {
        goto errorExit;
    }
    cmac_created = 1;

    // Skip to the meta-data position while calculating the cmac
    if(esfs_cmac_skip_to(file_handle, file_handle->tlv_properties.tlv_items[index].position) != ESFS_SUCCESS)
    {
        tr_err("esfs_read_meta_data() - pal_fsFseek() failed with pal status 0x%x", (unsigned int)res);
        goto errorExit;
    }

    // Read data
    // If required according to esfs_mode, the read data will be decrypted
    size_t num_bytes;
    if((file_handle->esfs_mode & ESFS_ENCRYPTED) != 0)
    {
        if(esfs_read_and_decrypt( file_handle,
                                  meta_data->value,
                                  file_handle->tlv_properties.tlv_items[index].length_in_bytes,
                                  &num_bytes
                                ) != ESFS_SUCCESS)
        {
            is_read_error = true;
        }
    }
    else
    {
        if(esfs_cmac_read(file_handle, meta_data->value, file_handle->tlv_properties.tlv_items[index].length_in_bytes, &num_bytes ) != ESFS_SUCCESS)
        {
            is_read_error = true;
        }
    }

    if(is_read_error || (num_bytes != file_handle->tlv_properties.tlv_items[index].length_in_bytes))
    {
        tr_err("esfs_read_meta_data() - read data failed is_read_error = %s and num_bytes  = %zu",
            is_read_error ? "true" : "false", num_bytes);
        goto errorExit;
    }

    // Skip to the end of the data section of the file.
    if(esfs_cmac_skip_to(file_handle ,file_handle->file_size - ESFS_CMAC_SIZE_IN_BYTES) != ESFS_SUCCESS)
    {
        goto errorExit;
    }

    // Return the cmac
    unsigned char cmac[ESFS_CMAC_SIZE_IN_BYTES];
    if(esfs_cmac_finish(file_handle, &cmac[0]) != ESFS_SUCCESS)
    {
        tr_err("esfs_read() - esfs_finish_cmac() failed");
        goto errorExit;
    }
    cmac_created = 0;

    // Before restoring old position, make sure offset_to_restore is not a negative number
    offset_to_restore = current_pos;
    if(offset_to_restore < 0)
    {
        tr_err("esfs_read_meta_data() failed - current_pos is negative");
        goto errorExit;
    }

    // Check the cmac and restore the file position to the saved position
    if(esfs_cmac_check_and_restore(file_handle, &cmac[0], offset_to_restore) != ESFS_SUCCESS)
    {
        tr_err("esfs_read_meta_data() - cmac that we read from the file does not match the one that we calculated");
        result = ESFS_CMAC_DOES_NOT_MATCH;
        goto errorExit;
    }

    // Update meta_data fields
    meta_data->type = file_handle->tlv_properties.tlv_items[index].type;
    meta_data->length_in_bytes = file_handle->tlv_properties.tlv_items[index].length_in_bytes;

    return ESFS_SUCCESS;

errorExit:
    if(cmac_created)
    {
        // Clean up cmac. Ignore error.
        (void)esfs_cmac_finish(file_handle, &cmac[0]);
    }
    return result;
}
