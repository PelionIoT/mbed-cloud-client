// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#ifndef _PAL_SST_H
#define _PAL_SST_H

#include <stdint.h>
#include "key_config_manager.h"
#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_sst.h
*  \brief PAL SST.
*   This file contains Secure Storage APIs and is part of the PAL Service API.
*   It provides read/write functionalities to SST and iterator capabilities.
*/

/*
* Pal SST item iterator
*/
typedef uintptr_t palSSTIterator_t;

/*
* Pal SST flags
*/

/*
* Write once flag. 
* When the flag is used, the item can only be written once and cannot be removed.
*/
#define PAL_SST_WRITE_ONCE_FLAG         (1 << 0)

/* 
* Confidentiality (encryption) flag.
*/
#define PAL_SST_CONFIDENTIALITY_FLAG    (1 << 1)

/*
* Replay protection flag.
* When this flag is used, the item cannot be physically removed (outside pal_SST APIs). 
*/
#define PAL_SST_REPLAY_PROTECTION_FLAG  (1 << 3)

/*
* PAL SST item info structure
*/
typedef struct palSSTItemInfo {
    size_t itemSize;          //!< PAL item size
    uint32_t SSTFlagsBitmap;  //!< PAL SST flags bitmap
} palSSTItemInfo_t;

/*! Writes a new item to storage. 
*
* The API supports writing empty items. When you write an item that has already been set, the API overwrites the set value, unless the write-once flag is turned on for the item.
*
* @param[in] itemName: The item name. Pelion client expects that the API support:
*                      - Name length of at least 120 characters.
*                      - Alphanumeric and '.', '-', '_' characters in the name.
* @param[in] itemBuffer: A pointer to the location in memory with the item to write.
*                        Can be NULL if ::itemBufferSize is 0.
* @param[in] itemBufferSize: The data length of the item in bytes.
*                            Can be 0 if ::itemBuffer is NULL.
* @param[in] SSTFlagsBitmap: PAL SST flag bitmap.
*
* \returns
*        PAL_SUCCESS on success.
*        PAL_ERR_SST_WRITE_PROTECTED when trying to set write-once value.
*        Other negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTSet(const char *itemName, const void *itemBuffer, size_t itemBufferSize, uint32_t SSTFlagsBitmap);

/*! Reads an item's data from storage.
*
* The API supports reading empty items.
* @param[in] itemName: The item name. Pelion client expects that the API support:
*                      - Name length of at least 120 characters. 
*                      - Alphanumeric and '.', '-', '_' characters in the name.
* @param[in/out] itemBuffer: A pointer to a memory buffer where the item will be read from storage.
*                            Can be NULL if ::itemBufferSize is 0.
* @param[in] itemBufferSize: The memory buffer in bytes.
*                            Can be 0 if ::itemBuffer is NULL.
* @param[out] actualItemSize: The actual size of the item.
*
* \return
*        PAL_SUCCESS on success.
*        PAL_ERR_SST_ITEM_NOT_FOUND if the item does not exist.
*        Other negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTGet(const char *itemName, void *itemBuffer, size_t itemBufferSize, size_t *actualItemSize);

/*! Gets item information.
*
* @param[in] itemName: The item name. Pelion client expects that the API support:
*                      - Name length of at least 120 characters.
*                      - Alphanumeric and '.', '-', '_' characters in the name.
* @param[out] palItemInfo: The item info.
*
* \return
*        PAL_SUCCESS on success.
*        PAL_ERR_SST_ITEM_NOT_FOUND if the item does not exist.
*        Other negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTGetInfo(const char *itemName, palSSTItemInfo_t *palItemInfo);

/*! Removes an item from storage, unless the write-once flag is turned on for the item.
*
* @param[in] itemName: The item name. Pelion client expects that the API support:
*                      - Name length of at least 120 characters. 
*                      - Alphanumeric and '.', '-', '_' characters in the name.
*
* \return
*        PAL_SUCCESS on success.
*        PAL_ERR_SST_WRITE_PROTECTED when trying to remove a write-once value.
*        Other negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTRemove(const char *itemName);

/*! Opens item iterator.
*
* @param[out] palSSTIterator: A pointer to the item iterator.
* @param[in] itemPrefix:  The prefix of the item name.
*
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTIteratorOpen(palSSTIterator_t *palSSTIterator, const char *itemPrefix);

/*! Iterates to next item.
*
* @param[in/out] palSSTIterator: A pointer to item iterator.
* @param[in/out] itemName:  A pointer to the item name buffer populated by the iterator. Must be supplied by the user.
* @param[in] itemNameSize: The size of the supplied item name buffer. Must be at least the length of itemName.
*
* \return
*        PAL_SUCCESS on success.
*        PAL_ERR_SST_ITEM_NOT_FOUND if the item does not exist.
*        Other negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTIteratorNext(palSSTIterator_t palSSTIterator, char *itemNameBuffer, size_t itemNameBufferSize);

/*! Closes item iterator.
*
* @param[in/out] palSSTIterator: A pointer to item iterator.
* @param[in] itemPrefix:  The prefix of the item name.
* 
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in the event of failure.
*/
kcm_status_e pal_SSTIteratorClose(palSSTIterator_t palSSTIterator);

/*! Remove all items and related data.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in the event of failure.
 */
kcm_status_e pal_SSTReset(void);

#ifdef __cplusplus
}
#endif

// endif


#endif //_PAL_SST_H

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
