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

#include "pal.h"
#include "pal_plat_update.h"

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "clock_config.h"
#include "fsl_flash.h"

#define TRACE_GROUP "PAL"

#define PAL_UPDATE_JOURNAL_SIZE 0x80000UL
#define PAL_UPDATE_JOURNAL_START_OFFSET 0x80000UL

#if (!defined(PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET))
#define PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET 0x80000UL
#endif

#define SIZEOF_SHA256 256/8
#define FIRMWARE_HEADER_MAGIC   0x5a51b3d4UL
#define FIRMWARE_HEADER_VERSION 1

PAL_PRIVATE FirmwareHeader_t g_palFirmwareHeader;
PAL_PRIVATE bool g_headerWasWritten = false;

PAL_PRIVATE flash_config_t g_flashDriver;


/*
 * call back functions
 *
 */

PAL_PRIVATE palImageSignalEvent_t g_palUpdateServiceCBfunc;

/*
 * WARNING: please do not change this function!
 * this function loads a call back function received from the upper layer (service).
 * the call back should be called at the end of each function (except pal_plat_imageGetDirectMemAccess)
 * the call back receives the event type that just happened defined by the ENUM  palImageEvents_t.
 *
 * if you will not call the call back at the end the service behaver will be undefined
 */
palStatus_t pal_plat_imageInitAPI(palImageSignalEvent_t CBfunction)
{
    if (!CBfunction)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
	g_palUpdateServiceCBfunc = CBfunction;
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_INIT);

	return PAL_SUCCESS;
}

palStatus_t pal_plat_imageDeInit(void)
{
	palStatus_t status = PAL_SUCCESS;
	return status;
}


palStatus_t pal_plat_imageGetMaxNumberOfImages(uint8_t *imageNumber)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageSetVersion(palImageId_t imageId, const palConstBuffer_t* version)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageGetDirectMemAccess(palImageId_t imageId, void** imagePtr, size_t *imageSizeInBytes)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageActivate(palImageId_t imageId)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}


palStatus_t pal_plat_imageGetActiveHash(palBuffer_t *hash)
{

    return PAL_ERR_NOT_IMPLEMENTED;
}

//Retrieve the version of the active image to version buffer with size set to version bufferLength.
palStatus_t pal_plat_imageGetActiveVersion (palBuffer_t* version)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}

//Writing the value of active image hash stored in hashValue to memory
palStatus_t pal_plat_imageWriteHashToMemory(const palConstBuffer_t* const hashValue)
{
	return PAL_ERR_NOT_IMPLEMENTED;
}


/*
 * init apis
 */



//fill the image header data for writing, the writing will occur in the 1st image write
palStatus_t pal_plat_imageSetHeader(palImageId_t imageId,palImageHeaderDeails_t *details)
{
    PAL_LOG_DBG(">>%s\r\n",__FUNCTION__);
    palStatus_t status = PAL_SUCCESS;
    g_headerWasWritten = false; // set that the image was not written yet
    memset(&g_palFirmwareHeader,0,sizeof(g_palFirmwareHeader));
    g_palFirmwareHeader.totalSize = details->imageSize + sizeof(FirmwareHeader_t);
    g_palFirmwareHeader.magic = FIRMWARE_HEADER_MAGIC;
    g_palFirmwareHeader.version = FIRMWARE_HEADER_VERSION;
    g_palFirmwareHeader.firmwareVersion = details->version;

    memcpy(g_palFirmwareHeader.firmwareSHA256,details->hash.buffer,SIZEOF_SHA256);
    /*
     * calculating and setting the checksum of the header.
     * Have to call to crcInit  before use.
     */
   // crcInit();
   // g_palFirmwareHeader.checksum =  crcFast((const unsigned char *)&g_palFirmwareHeader, (int)sizeof(g_palFirmwareHeader));
    return  status;
}



palStatus_t pal_plat_imageReserveSpace(palImageId_t imageId, size_t imageSize)
{
    status_t result = PAL_SUCCESS;
    memset(&g_flashDriver, 0, sizeof(g_flashDriver));
    result = FLASH_Init(&g_flashDriver);
    if (kStatus_FLASH_Success != result)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
        return PAL_ERR_UPDATE_ERROR;
    }

    result = FLASH_Erase(&g_flashDriver, PAL_UPDATE_JOURNAL_START_OFFSET, imageSize, kFLASH_apiEraseKey);
    if (kStatus_FLASH_Success != result)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
        return PAL_ERR_UPDATE_ERROR;
    }

    result = FLASH_VerifyErase(&g_flashDriver, PAL_UPDATE_JOURNAL_START_OFFSET, imageSize, kFLASH_marginValueUser);
    if (kStatus_FLASH_Success != result)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
        return PAL_ERR_UPDATE_ERROR;
    }
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_PREPARE);

    return PAL_SUCCESS;
}





/*
 * write API
 */





palStatus_t pal_plat_imageWrite(palImageId_t imageId, size_t offset, palConstBuffer_t *chunk)
{
    status_t result = PAL_SUCCESS;
    uint32_t failAddr, failDat;
    //if header was not written - write header
    if (!g_headerWasWritten)
    {
        result = FLASH_Program(
            &g_flashDriver,
            PAL_UPDATE_JOURNAL_START_OFFSET,
            (uint32_t *)(&g_palFirmwareHeader),
            sizeof(g_palFirmwareHeader)
            );
		if (kStatus_FLASH_Success != result)
		{
		    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
		    return PAL_ERR_UPDATE_ERROR;
		}
		g_headerWasWritten = true;
    }
    result = FLASH_Program(
        &g_flashDriver,
        (PAL_UPDATE_JOURNAL_START_OFFSET + sizeof(g_palFirmwareHeader) + offset),
        (uint32_t *)(chunk->buffer),
        chunk->bufferLength
        );
    if (kStatus_FLASH_Success != result)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
        return PAL_ERR_UPDATE_ERROR;
    }

    /* Program Check user margin levels */
    result = FLASH_VerifyProgram(
        &g_flashDriver,
        (PAL_UPDATE_JOURNAL_START_OFFSET + sizeof(g_palFirmwareHeader) + offset),
        chunk->bufferLength,
        (const uint32_t *)(chunk->buffer),
        kFLASH_marginValueUser,
        &failAddr,
        &failDat
        );
    if (kStatus_FLASH_Success != result)
    {
        g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_ERROR);
        return PAL_ERR_UPDATE_ERROR;
    }
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_WRITE);
    return PAL_SUCCESS;
}


/*
 * read APIs
 */




palStatus_t pal_plat_imageReadToBuffer(palImageId_t imageId, size_t offset, palBuffer_t *chunk)
{
    uint32_t imageSize = g_palFirmwareHeader.totalSize - sizeof(g_palFirmwareHeader); //totalSize - headerSize
    if ((offset + chunk->maxBufferLength) <= imageSize)
    {
        chunk->bufferLength = chunk->maxBufferLength;
    }
    else
    {
        chunk->bufferLength =chunk->maxBufferLength + imageSize - offset;
    }
    memcpy(chunk->buffer, (void*)(PAL_UPDATE_JOURNAL_START_OFFSET + sizeof(g_palFirmwareHeader) + offset) , chunk->bufferLength);
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_READTOBUFFER);
    return PAL_SUCCESS;
}



/*
 * commit functions
 * */



palStatus_t pal_plat_imageFlush(palImageId_t package_id)
{
    PAL_LOG_DBG(">>%s\r\n",__FUNCTION__);
    g_palUpdateServiceCBfunc(PAL_IMAGE_EVENT_FINALIZE);
    PAL_LOG_DBG("<<%s\r\n",__FUNCTION__);
    return PAL_SUCCESS;
}
