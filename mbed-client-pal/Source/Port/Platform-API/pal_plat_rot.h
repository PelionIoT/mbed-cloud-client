/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
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


#ifndef _PAL_PLAT_ROT_H
#define _PAL_PLAT_ROT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"

#include <stdint.h>
#include <stddef.h>

#define PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES 32
#define PAL_DEVICE_KEY_SIZE_IN_BITS (128)
#define PAL_DEVICE_KEY_SIZE_IN_BYTES (PAL_DEVICE_KEY_SIZE_IN_BITS / 8)

/*! \file pal_plat_rot.h
*  \brief PAL RoT - platform.
*   This file contains the RoT (Root of Trust) API.
*/

/*! \brief Retrieves a platform Root of Trust certificate.
 *
 * @param[in,out] *keyBuf A pointer to the buffer that holds the RoT. The buffer needs to be able to hold 16 bytes of data.
 * @param[in] keyLenBytes The size of the buffer must be 16 bytes.
 *
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osGetRoT(uint8_t *keyBuf, size_t keyLenBytes);

#if PAL_USE_HW_ROT
/*! \brief Retrieves a hardware platform Root of Trust certificate.
 *
 * This function must be implemented for hardware RoT configuration.
 *
 * @param[in,out] *keyBuf A pointer to the buffer that holds the RoT. The buffer needs to be able to hold 16 bytes of data.
 * @param[in] keyLenBytes The size of the buffer must be 16 bytes.
 *
 * \return PAL_SUCCESS(0) in case of success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osGetRoTFromHW(uint8_t *keyBuf, size_t keyLenBytes);
#endif

#if defined (PAL_USE_HW_ROT) && (PAL_USE_HW_ROT==0)
/*! \brief Sets a Root of Trust certificate.
 *
 * The size of the Root of Trust must be 16 bytes.
 * This function is not implemented for hardware RoT configuration.
 *
 * @param[in] keyBuf A 16-byte buffer with a Root of Trust key to set.
 * @param[in] keyLenBytes The size of the buffer must be 16 bytes.
 *
 * \return PAL_SUCCESS in case of success and one of the following error codes in case of failure:
 * \return PAL_ERR_ITEM_EXIST - RoT key already exists.
 * \return PAL_ERR_INVALID_ARGUMENT - invalid parameter.
 * \return PAL_ERR_GENERIC_FAILURE - set operation failed.
 */
palStatus_t pal_plat_osSetRoT(uint8_t *keyBuf, size_t keyLenBytes);
#endif

#ifdef __cplusplus
}
#endif
#endif //_PAL_PLAT_ROT_H
