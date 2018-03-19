/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <pal.h>
#include "pal_plat_update.h"
#include "pal_update.h"
#include "pal_macros.h"

PAL_PRIVATE uint8_t palUpdateInitFlag = 0;

#define PAL_KILOBYTE 1024

#ifndef PAL_UPDATE_IMAGE_LOCATION
#error "Please definee PAL_UPDATE_IMAGE_LOCATION to UPDATE_USE_FLASH (value 1) or UPDATE_USE_FS(2)"
#endif

#if (PAL_UPDATE_IMAGE_LOCATION == PAL_UPDATE_USE_FS)
#define SEEK_POS_INVALID            0xFFFFFFFF
PAL_PRIVATE FirmwareHeader_t pal_pi_mbed_firmware_header;
PAL_PRIVATE palImageSignalEvent_t g_palUpdateServiceCBfunc;
PAL_PRIVATE palFileDescriptor_t image_file[IMAGE_COUNT_MAX];
PAL_PRIVATE bool last_read_nwrite[IMAGE_COUNT_MAX];
PAL_PRIVATE uint32_t last_seek_pos[IMAGE_COUNT_MAX];
PAL_PRIVATE bool valid_index(uint32_t index);
PAL_PRIVATE size_t safe_read(uint32_t index, size_t offset, uint8_t *buffer, uint32_t size);
PAL_PRIVATE size_t safe_write(uint32_t index, size_t offset, const uint8_t *buffer, uint32_t size);
PAL_PRIVATE bool open_if_necessary(uint32_t index, bool read_nwrite);
PAL_PRIVATE bool seek_if_necessary(uint32_t index, size_t offset, bool read_nwrite);
PAL_PRIVATE bool close_if_necessary(uint32_t index);
PAL_PRIVATE const char *image_path_alloc_from_index(uint32_t index);
PAL_PRIVATE const char *header_path_alloc_from_index(uint32_t index);
PAL_PRIVATE const char *path_join_and_alloc(const char * const * path_list);

PAL_PRIVATE palStatus_t pal_set_fw_header(palImageId_t index, FirmwareHeader_t *headerP);
PAL_PRIVATE uint32_t internal_crc32(const uint8_t* buffer, uint32_t length);


char* pal_imageGetFolder(void)
{
    return PAL_UPDATE_FIRMWARE_DIR;
}


palStatus_t pal_imageInitAPI(palImageSignalEvent_t CBfunction)
{
    palStatus_t status = PAL_SUCCESS;
    //printf("pal_imageInitAPI\r\n");
    PAL_MODULE_INIT(palUpdateInitFlag);

    // create absolute path.


    pal_fsMkDir(PAL_UPDATE_FIRMWARE_DIR);

    g_palUpdateServiceCBfunc = CBfunction;
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_INIT);
    return status;
}

palStatus_t pal_imageDeInit(void)
{
    //printf("pal_plat_imageDeInit\r\n");
    PAL_MODULE_DEINIT(palUpdateInitFlag);

    for (int i = 0; i < IMAGE_COUNT_MAX; i++)
    {
        close_if_necessary(i);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_imagePrepare(palImageId_t imageId, palImageHeaderDeails_t *headerDetails)
{
    //printf("pal_imagePrepare(imageId=%lu, size=%lu)\r\n", imageId, headerDetails->imageSize);
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t ret;
    uint8_t *buffer;

    // write the image header to file system
    memset(&pal_pi_mbed_firmware_header,0,sizeof(pal_pi_mbed_firmware_header));
    pal_pi_mbed_firmware_header.totalSize = headerDetails->imageSize;
    pal_pi_mbed_firmware_header.magic = FIRMWARE_HEADER_MAGIC;
    pal_pi_mbed_firmware_header.version = FIRMWARE_HEADER_VERSION;
    pal_pi_mbed_firmware_header.firmwareVersion = headerDetails->version;
    memcpy(pal_pi_mbed_firmware_header.firmwareSHA256,headerDetails->hash.buffer,SIZEOF_SHA256);

    pal_pi_mbed_firmware_header.checksum = internal_crc32((uint8_t *) &pal_pi_mbed_firmware_header,
                                                          sizeof(pal_pi_mbed_firmware_header));

    ret = pal_set_fw_header(imageId, &pal_pi_mbed_firmware_header);

    /*Check that the size of the image is valid and reserve space for it*/
    if (ret == PAL_SUCCESS)
    {
        buffer = malloc(PAL_KILOBYTE);
        if (NULL != buffer)
        {
        	uint32_t writeCounter = 0;
			memset(buffer,0,PAL_KILOBYTE);
			while(writeCounter <= headerDetails->imageSize)
			{
                int written = safe_write(imageId,0,buffer,PAL_KILOBYTE);
                writeCounter+=PAL_KILOBYTE;
                if (PAL_KILOBYTE != written)
                {
                    ret = PAL_ERR_UPDATE_ERROR;
                }
			}
			if ((PAL_SUCCESS == ret) && (writeCounter < headerDetails->imageSize))
			{
				//writing the last bytes
                int written = safe_write(imageId,0,buffer,(headerDetails->imageSize - writeCounter));
                if ((headerDetails->imageSize - writeCounter) != written)
                {
                    ret = PAL_ERR_UPDATE_ERROR;
                }
			}
			free(buffer);
			if (PAL_SUCCESS == ret)
			{
				ret = pal_fsFseek(&(image_file[imageId]),0,PAL_FS_OFFSET_SEEKSET);
			}
			else
			{
				pal_fsUnlink(image_path_alloc_from_index(imageId));
			}
        }
        else
        {
        	ret = PAL_ERR_NO_MEMORY;
        }
    }
    if (PAL_SUCCESS == ret)
    {
    	g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_PREPARE);
    }
    else
    {
    	g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
    }


    return ret;
}

palStatus_t pal_imageWrite(palImageId_t imageId, size_t offset, palConstBuffer_t *chunk)
{
    //printf("pal_imageWrite(imageId=%lu, offset=%lu)\r\n", imageId, offset);
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t ret = PAL_ERR_UPDATE_ERROR;

    int xfer_size_or_error = safe_write(imageId, offset, chunk->buffer, chunk->bufferLength);
    if ((xfer_size_or_error < 0) || ((uint32_t)xfer_size_or_error != chunk->bufferLength))
    {
        //printf("Error writing to file\r\n");
    }
    else
    {
        ret = PAL_SUCCESS;
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_WRITE);
    }

    return ret;
}

palStatus_t  pal_imageFinalize(palImageId_t imageId)
{
    //printf("pal_imageFinalize(id=%i)\r\n", imageId);
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t ret = PAL_ERR_UPDATE_ERROR;

    if (close_if_necessary(imageId))
    {
        ret = PAL_SUCCESS;
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_FINALIZE);
    }

    return ret;
}

palStatus_t pal_imageGetDirectMemoryAccess(palImageId_t imageId, void** imagePtr, size_t* imageSizeInBytes)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageGetDirectMemAccess(imageId, imagePtr, imageSizeInBytes);
    return status;
}

palStatus_t pal_imageReadToBuffer(palImageId_t imageId, size_t offset, palBuffer_t *chunk)
{
    //printf("pal_imageReadToBuffer(imageId=%lu, offset=%lu)\r\n", imageId, offset);
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t ret = PAL_ERR_UPDATE_ERROR;

    int xfer_size_or_error = safe_read(imageId, offset, chunk->buffer, chunk->maxBufferLength);
    if (xfer_size_or_error < 0)
    {
        //printf("Error reading from file\r\n");
    }
    else
    {
        chunk->bufferLength = xfer_size_or_error;
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_READTOBUFFER);
        ret = PAL_SUCCESS;
    }

    return ret;
}

palStatus_t pal_imageActivate(palImageId_t imageId)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageActivate(imageId);
    return status;
}

palStatus_t pal_imageGetFirmwareHeaderData(palImageId_t imageId, palBuffer_t *headerData)
{
		palStatus_t ret = PAL_SUCCESS;
		palFileDescriptor_t file = 0;
		size_t xfer_size;
        if (NULL == headerData)
        {
            return PAL_ERR_NULL_POINTER;
        }
		if (headerData->maxBufferLength < sizeof(palFirmwareHeader_t))
		{
			PAL_LOG(ERR, "Firmware header buffer size is too small(is %" PRIu32 " needs to be at least %zu)\r\n"
					    ,headerData->maxBufferLength, sizeof(palFirmwareHeader_t));
			return PAL_ERR_INVALID_ARGUMENT;
		}

		const char *file_path = header_path_alloc_from_index(imageId);
		if (file_path)
		{
			ret = pal_fsFopen(file_path, PAL_FS_FLAG_READONLY, &file);
			if (ret == PAL_SUCCESS)
			{
				ret = pal_fsFread(&file, headerData->buffer, sizeof(palFirmwareHeader_t), &xfer_size);
				if (PAL_SUCCESS == ret)
				{
					headerData->bufferLength = xfer_size;
				}
				pal_fsFclose(&file);
			}
			free((void*)file_path);
		}
		else
		{
			ret = PAL_ERR_NO_MEMORY;
		}
	    return ret;
}

palStatus_t pal_imageGetActiveHash(palBuffer_t *hash)
{
    //printf("pal_imageGetActiveHash\r\n");
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t ret;

    if (hash->maxBufferLength < SIZEOF_SHA256)
    {
        ret = PAL_ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    hash->bufferLength = 0;
    memset(hash->buffer, 0, hash->maxBufferLength);

    ret = pal_plat_imageGetActiveHash(hash);
    if (ret == PAL_SUCCESS)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_GETACTIVEHASH);
    }

exit:
    return ret;
}

palStatus_t pal_imageGetActiveVersion(palBuffer_t *version)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageGetActiveVersion(version);
    return status;
}

palStatus_t pal_imageWriteDataToMemory(palImagePlatformData_t dataId, const palConstBuffer_t * const dataBuffer)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    // this switch is for further use when there will be more options
    switch(dataId)
    {
    case PAL_IMAGE_DATA_HASH:
        status = pal_plat_imageWriteHashToMemory(dataBuffer);
        break;
    default:
        {
            PAL_LOG(ERR, "Update image write to memory error");
            status = PAL_ERR_GENERIC_FAILURE;
        }
    }
    return status;
}

PAL_PRIVATE palStatus_t pal_set_fw_header(palImageId_t index, FirmwareHeader_t *headerP)
{
    palStatus_t ret;
    palFileDescriptor_t file = 0;
    size_t xfer_size;

    const char *file_path = header_path_alloc_from_index(index);
    ret = pal_fsFopen(file_path, PAL_FS_FLAG_READWRITETRUNC, &file);
    if (ret != PAL_SUCCESS)
    {
        //printf("pal_fsFopen returned 0x%x\r\n", ret);
        goto exit;
    }

    ret = pal_fsFwrite(&file, headerP, sizeof(FirmwareHeader_t), &xfer_size);
    if (ret != PAL_SUCCESS)
    {
        //printf("pal_fsFread returned 0x%x\r\n", ret);
        goto exit;
    }
    else if (xfer_size != sizeof(FirmwareHeader_t))
    {
        //printf("Size written %lu expected %lu\r\n", xfer_size, sizeof(FirmwareHeader_t));
        goto exit;
    }

    ret = PAL_SUCCESS;

exit:
    if (file != 0)
    {
        ret = pal_fsFclose(&file);
        if (ret != PAL_SUCCESS)
        {
            //printf("Error closing file %s\r\n", file_path);
            ret = PAL_ERR_UPDATE_ERROR;
        }
    }
    free((void*)file_path);

    return ret;
}

/**
 * @brief Bitwise CRC32 calculation
 * @details Modified from ARM Keil code:
 *          http://www.keil.com/appnotes/docs/apnt_277.asp
 *
 * @param buffer Input byte array.
 * @param length Number of bytes in array.
 *
 * @return CRC32
 */
PAL_PRIVATE uint32_t internal_crc32(const uint8_t* buffer,
                                    uint32_t length)
{
    const uint8_t* current = buffer;
    uint32_t crc = 0xFFFFFFFF;

    while (length--)
    {
        crc ^= *current++;

        for (uint32_t counter = 0; counter < 8; counter++)
        {
            if (crc & 1)
            {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else
            {
                crc = crc >> 1;
            }
        }
    }

    return (crc ^ 0xFFFFFFFF);
}

PAL_PRIVATE bool valid_index(uint32_t index)
{
    return (index < IMAGE_COUNT_MAX);
}

PAL_PRIVATE size_t safe_read(uint32_t index, size_t offset, uint8_t *buffer, uint32_t size)
{
    const bool read_nwrite = true;
    size_t xfer_size = 0;
    palStatus_t status;

    if ((!valid_index(index)) || (!open_if_necessary(index, read_nwrite)) || (!seek_if_necessary(index, offset, read_nwrite)))
    {
        return 0;
    }

    status = pal_fsFread(&(image_file[index]), buffer, size, &xfer_size);
    if (status == PAL_SUCCESS)
    {
    	last_read_nwrite[index] = read_nwrite;
		last_seek_pos[index] += xfer_size;
    }

    return xfer_size;
}

PAL_PRIVATE size_t safe_write(uint32_t index, size_t offset, const uint8_t *buffer, uint32_t size)
{
    const bool read_nwrite = false;
    size_t xfer_size = 0;
    palStatus_t status;
    if ((!valid_index(index)) ||  (!open_if_necessary(index, read_nwrite)) ||  (!seek_if_necessary(index, offset, read_nwrite)))
    {
        return 0;
    }
    status = pal_fsFseek(&(image_file[index]), offset, PAL_FS_OFFSET_SEEKSET);
    if (status == PAL_SUCCESS)
    {
    status  = pal_fsFwrite(&(image_file[index]), buffer, size, &xfer_size);
		if (status == PAL_SUCCESS)
		{
			last_read_nwrite[index] = read_nwrite;
			last_seek_pos[index] += xfer_size;

			if (size != xfer_size)
			{
				//printf("WRONG SIZE expected %u got %lu\r\n", size, xfer_size);
				return 0;
			}

		}
    }

    return xfer_size;
}

PAL_PRIVATE bool open_if_necessary(uint32_t index, bool read_nwrite)
{
    if (!valid_index(index))
    {
        return false;
    }
    if ( (unsigned int*)image_file[index] == NULL )
    {
        const char *file_path = image_path_alloc_from_index(index);
        pal_fsFileMode_t mode = read_nwrite ? PAL_FS_FLAG_READWRITE : PAL_FS_FLAG_READWRITETRUNC;

        palStatus_t ret = pal_fsFopen(file_path, mode, &(image_file[index]));
        free((void*)file_path);
        last_seek_pos[index] = 0;
        if (ret != PAL_SUCCESS)
        {
            return false;
        }
    }

    return true;
}

PAL_PRIVATE bool seek_if_necessary(uint32_t index, size_t offset, bool read_nwrite)
{
    if (!valid_index(index))
    {
        return false;
    }

    if ((read_nwrite != last_read_nwrite[index]) ||
        (offset != last_seek_pos[index]))
    {
        palStatus_t ret = pal_fsFseek(&(image_file[index]), offset, PAL_FS_OFFSET_SEEKSET);
        if (ret != PAL_SUCCESS)
        {
            last_seek_pos[index] = SEEK_POS_INVALID;
            return false;
        }
    }

    last_read_nwrite[index] = read_nwrite;
    last_seek_pos[index] = offset;

    return true;
}

PAL_PRIVATE bool close_if_necessary(uint32_t index)
{
    if (!valid_index(index))
    {
        return false;
    }

    palFileDescriptor_t file = image_file[index];
    image_file[index] = 0;
    last_seek_pos[index] = SEEK_POS_INVALID;

    if (file != 0)
    {
        palStatus_t ret = pal_fsFclose(&file);
        if (ret != 0)
        {
            return false;
        }
    }

    return true;
}

PAL_PRIVATE const char *image_path_alloc_from_index(uint32_t index)
{
    char file_name[32] = {0};
    snprintf(file_name, sizeof(file_name)-1, "image_%" PRIu32 ".bin", index);
    file_name[sizeof(file_name) - 1] = 0;
    const char * const path_list[] = {
         (char*)PAL_UPDATE_FIRMWARE_DIR,
        file_name,
        NULL
    };

    return path_join_and_alloc(path_list);
}

PAL_PRIVATE const char *header_path_alloc_from_index(uint32_t index)
{
    char file_name[32] = {0};

    if (ACTIVE_IMAGE_INDEX == index)
    {
        snprintf(file_name, sizeof(file_name)-1, "header_active.bin");
    }
    else
    {
        snprintf(file_name, sizeof(file_name)-1, "header_%" PRIu32 ".bin", index);
    }

    const char * const path_list[] = {
         (char*)PAL_UPDATE_FIRMWARE_DIR,
        file_name,
        NULL
    };

    return path_join_and_alloc(path_list);
}


PAL_PRIVATE const char *path_join_and_alloc(const char * const * path_list)
{
    uint32_t string_size = 1;
    uint32_t pos = 0;

    // Determine size of string to return
    while (path_list[pos] != NULL)
    {
        // Size of string and space for separator
        string_size += strlen(path_list[pos]) + 1;
        pos++;
    }

    // Allocate and initialize memory
    char *path = (char*)malloc(string_size);
    if (NULL != path)
    {
    	memset(path, 0, string_size);
    	// Write joined path
    	pos = 0;
    	while (path_list[pos] != NULL)
    	{
    		bool has_slash = '/' == path_list[pos][strlen(path_list[pos]) - 1];
    		bool is_last = NULL == path_list[pos + 1];
            strncat(path, path_list[pos], string_size - strlen(path) - 1);
    		if (!has_slash && !is_last)
    		{
                strncat(path, "/", string_size - strlen(path) - 1);
    		}
    		pos++;
    	}
    }
    return path;
}




#elif (PAL_UPDATE_IMAGE_LOCATION == PAL_UPDATE_USE_FLASH)

palStatus_t pal_imageInitAPI(palImageSignalEvent_t CBfunction)
{
    PAL_MODULE_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageInitAPI(CBfunction);
    return status;
}

palStatus_t pal_imageDeInit(void)
{
    PAL_MODULE_DEINIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageDeInit();
    return status;
}



palStatus_t pal_imagePrepare(palImageId_t imageId, palImageHeaderDeails_t *headerDetails)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    pal_plat_imageSetHeader(imageId,headerDetails);
    status = pal_plat_imageReserveSpace(imageId, headerDetails->imageSize);

    return status;
}

palStatus_t pal_imageWrite (palImageId_t imageId, size_t offset, palConstBuffer_t *chunk)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageWrite(imageId, offset, chunk);
    return status;
}

palStatus_t  pal_imageFinalize(palImageId_t imageId)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageFlush(imageId);
    return status;
}

palStatus_t pal_imageGetDirectMemoryAccess(palImageId_t imageId, void** imagePtr, size_t* imageSizeInBytes)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageGetDirectMemAccess(imageId, imagePtr, imageSizeInBytes);
    return status;
}

palStatus_t pal_imageReadToBuffer(palImageId_t imageId, size_t offset, palBuffer_t *chunk)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;

    status = pal_plat_imageReadToBuffer(imageId,offset,chunk);
    return status;
}

palStatus_t pal_imageActivate(palImageId_t imageId)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageActivate(imageId);
    return status;
}

palStatus_t pal_imageGetActiveHash(palBuffer_t *hash)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageGetActiveHash(hash);
    return status;
}

palStatus_t pal_imageGetActiveVersion(palBuffer_t *version)
{
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_imageGetActiveVersion(version);
    return status;
}

palStatus_t pal_imageWriteDataToMemory(palImagePlatformData_t dataId, const palConstBuffer_t * const dataBuffer)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_MODULE_IS_INIT(palUpdateInitFlag);
    // this switch is for further use when there will be more options
    switch(dataId)
    {
    case PAL_IMAGE_DATA_HASH:
        status = pal_plat_imageWriteHashToMemory(dataBuffer);
        break;
    default:
        {
            PAL_LOG(ERR, "Update write data to mem status %d", (int)dataId);
            status = PAL_ERR_GENERIC_FAILURE;
        }
    }
    return status;
}

#endif
