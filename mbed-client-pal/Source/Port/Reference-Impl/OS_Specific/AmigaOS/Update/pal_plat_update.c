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

#include "pal_plat_update.h"


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

palStatus_t pal_plat_imageGetActiveHash(palBuffer_t* hash)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageGetActiveVersion (palBuffer_t* version)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageWriteHashToMemory(const palConstBuffer_t* const hashValue)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_imageSetHeader(palImageId_t imageId, palImageHeaderDeails_t* details)
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

//
palStatus_t pal_plat_imageFlush(palImageId_t package_id)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}
