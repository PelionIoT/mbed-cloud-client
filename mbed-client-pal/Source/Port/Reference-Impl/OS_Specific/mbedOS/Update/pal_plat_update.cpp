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

#include <mbed.h>
#include <pal.h>
#include <pal_plat_update.h>

#define TRACE_GROUP "PAL"

#ifndef PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET
#ifdef MBED_CONF_MBED_CLIENT_PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET
#define PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET MBED_CONF_MBED_CLIENT_PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET
#else  // MBED_CONF_MBED_CLIENT_PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET
#define PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET 0
#endif // MBED_CONF_MBED_CLIENT_PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET
#endif // PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET

palStatus_t pal_plat_imageInitAPI(palImageSignalEvent_t CBfunction)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageDeInit(void)
{
    return PAL_ERR_NOT_IMPLEMENTED;
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
    palStatus_t ret = PAL_ERR_UPDATE_ERROR;
    uint32_t read_offset = PAL_UPDATE_ACTIVE_METADATA_HEADER_OFFSET +
                            offsetof(FirmwareHeader_t, firmwareSHA256);

    FlashIAP flash;
    int rc = -1;

    rc = flash.init();
    if (rc != 0)
    {
        PAL_LOG_ERR("flash init failed\r\n");
        goto exit;
    }


    rc = flash.read(hash->buffer, read_offset, SIZEOF_SHA256);
    if (rc != 0)
    {
        PAL_LOG_ERR("flash read failed\r\n");
        goto exit;
    }

    hash->bufferLength = SIZEOF_SHA256;

    rc = flash.deinit();
    if (rc != 0)
    {
        PAL_LOG_ERR("flash deinit failed\r\n");
        goto exit;
    }

    ret = PAL_SUCCESS;

exit:
    return ret;
}

palStatus_t pal_plat_imageGetActiveVersion (palBuffer_t* version)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageWriteHashToMemory(const palConstBuffer_t* const hashValue)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageSetHeader(palImageId_t imageId, palImageHeaderDeails_t *details)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageReserveSpace(palImageId_t imageId, size_t imageSize)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageWrite(palImageId_t imageId, size_t offset, palConstBuffer_t *chunk)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageReadToBuffer(palImageId_t imageId, size_t offset, palBuffer_t *chunk)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageFlush(palImageId_t package_id)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}
