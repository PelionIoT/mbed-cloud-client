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


#ifndef PAL_PLAT_UPDATE_HEADER
#define PAL_PLAT_UPDATE_HEADER

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"


/*! \file pal_plat_update.h
 *  \brief PAL update - platform.
 *   This file contains the firmware update APIs that need to be implemented in the platform layer.
 */


/*! \brief Set the callback function that is called before the end of each API, except for `imageGetDirectMemAccess`.
 * @param[in] CBfunction A pointer to the callback function.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageInitAPI(palImageSignalEvent_t CBfunction);


/*! \brief Clear all the resources used by the `pal_update` APIs.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageDeInit(void);

/*! \brief Set the `imageNumber` to the number of available images. You can do this through the hard coded define inside the linker script.
 * @param[out] imageNumber The total number of images the system supports.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageGetMaxNumberOfImages(uint8_t* imageNumber);

/*! \brief Claim space in the relevant storage region for `imageId` with the size of the image.
 * @param[in] imageId The image ID.
 * @param[in] imageSize The size of the image.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageReserveSpace(palImageId_t imageId, size_t imageSize);


/*! \brief Set up the details for the image header.
 *
 * The data is written when the image write is called for the first time.
 * @param[in] imageId The image ID.
 * @param[in] details The data needed to build the image header.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageSetHeader(palImageId_t imageId,palImageHeaderDeails_t* details);

/*! \brief Write data from a chunk buffer to an image.
 * @param[in] imageId The image ID.
 * @param[in] offset The relative offset to write the data into.
 * @param[in] chunk A pointer to the struct containing the data and the data length to write.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_imageWrite(palImageId_t imageId, size_t offset, palConstBuffer_t* chunk);

/*! \brief Update the image version of `imageId`.
 * @param[in] imageId The image ID.
 * @param[in] version The new image version and its length.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageSetVersion(palImageId_t imageId, const palConstBuffer_t* version);

/*! \brief Flush the entire image data after writing ends for `imageId`.
 * @param[in] imageId The image ID.
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_imageFlush(palImageId_t imageId);

/*! \brief Verify whether the `imageId` is readable.
 *
 * The function also sets `imagePtr` to point to the beginning of the image in the memory and `imageSizeInBytes` to the image size.
* @param[in] imageId The image ID.
* @param[out] imagePtr A pointer to the start of the image.
* @param[out] imageSizeInBytes The size of the image.
* \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure and sets `imagePtr` to NULL.
*/
palStatus_t pal_plat_imageGetDirectMemAccess(palImageId_t imageId, void** imagePtr, size_t* imageSizeInBytes);


/*! \brief Read the max of chunk `maxBufferLength` bytes from the `imageId` with relative offset and store it in chunk buffer.
 *
 * Set the chunk `bufferLength` value to the actual number of bytes read.
 * \note Please use this API in case the image is not directly accessible via the `imageGetDirectMemAccess` function.
 * @param[in] imageId The image ID.
 * @param[in] offset The offset to start reading from.
 * @param[out] chunk The data and actual bytes read.
 */
palStatus_t pal_plat_imageReadToBuffer(palImageId_t imageId, size_t offset, palBuffer_t* chunk);

/*! \brief Set the `imageId` to be the active image after device reset.
 * @param[in] imageId The image ID.
 */
palStatus_t pal_plat_imageActivate(palImageId_t imageId);

/*! \brief Retrieve the hash value of the active image to the hash buffer with the max size hash `maxBufferLength` and set the hash `bufferLength` to the hash size.
 * @param[out] hash The hash and actual size of hash read.
 */
palStatus_t pal_plat_imageGetActiveHash(palBuffer_t* hash);

/*! \brief Retrieve the version of the active image to the version buffer with the size set to version `bufferLength`.
 * @param[out] version The version and actual size of version read.
 */
palStatus_t pal_plat_imageGetActiveVersion (palBuffer_t* version);

/*! Write the `dataId` stored in `dataBuffer` to the memory accessible to the bootloader. Currently, only HASH is available.
 * @param[in] hashValue The data and size of the HASH.
 */
palStatus_t pal_plat_imageWriteHashToMemory(const palConstBuffer_t* const hashValue);




#endif /* SOURCE_PAL_IMPL_MODULES_UPDATE_PAL_PALT_UPDATE_H_ */
#ifdef __cplusplus
}
#endif
