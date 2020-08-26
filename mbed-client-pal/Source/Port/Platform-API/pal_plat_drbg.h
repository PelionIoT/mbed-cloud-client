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


#ifndef _PAL_PLAT_DRBG_H
#define _PAL_PLAT_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"


/*! \file pal_plat_drbg.h
 *  \brief PAL DRBG - platform.
 *   This file contains the real-time OS APIs that need to be implemented in the platform layer.
 */

// This is the kv_key value used by Mbed OS PSA APIs for entropy initialization. Using the save value for DRBG to maintain
// backwards compatibility. This was added for backwards compatibility between Mbed OS 5.15 and Mbed OS 6.
// Previously all non-TRNG targets used PSA to inject entropy, but if application now uses direct KVStore mode (which is default)
// we need to ensure that we use the same name for the kv_key.
#define ENTROPY_RANDOM_SEED "B#S9---D"

/*! \brief Initialize all data structures (semaphores, mutexes, memory pools, message queues) at system initialization.
 *
 *   In case of a failure in any of the initializations, the function returns an error and stops the rest of the initializations.
 * \return PAL_SUCCESS(0) in case of success, PAL_ERR_CREATION_FAILED in case of failure.
 */
palStatus_t pal_plat_DRBGInit(void);

/*! \brief De-initialize thread objects.
 */
palStatus_t pal_plat_DRBGDestroy(void);

// XXX: following two are really easy to mix up, a better naming needs to be done
//
// * pal_plat_osRandomBuffer_public() - The one which is called by pal_osRandomBuffer(), one which
//                                      will block until there is enough entropy harvested
//
// * pal_plat_osRandomBuffer() - The lower level part, used by pal_plat_osRandomBuffer_public(),
//                                  this is nonblocking version which will return as much as possible.
//                               Perhaps this should be pal_plat_GetosRandomBufferFromHW() to align
//                               with logic used with similar purpose function as pal_plat_osGetRoTFromHW().

/*! \brief Generate a random number into the given buffer with the given size in bytes.
 *
 * @param[out] randomBuf A buffer to hold the generated number.
 * @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
 * @param[out] actualRandomSizeBytes The actual size of the written random data to the output buffer.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 \note In case the platform was able to provide random data with non-zero size and less than `bufSizeBytes`the function must return `PAL_ERR_RTOS_TRNG_PARTIAL_DATA`
 */
palStatus_t pal_plat_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

/*! \brief Generate random number into given buffer with given size in bytes.
 *
 * @param[out] randomBuf A buffer to hold the generated number.
 * @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
 *
 * \note `pal_init()` MUST be called before this function
 * \note If non-volatile entropy is expected, the entropy must have been injected before this function is called. Non-volatile entropy may be injected using `pal_plat_osEntropyInject()`.
 * \return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes);

/*! \brief Direct read from internal KVStore used for entropy injection with non-TRNG.
 *
 * @param[out] buffer_actual_size_out Size of data actually read from KVStore.
 * @param[in] KVStore kv_key item name to be read.
 * @param[in] buffer The buffer where to read.
 * @param[in] buffer_size The size of the buffer given.
 *
 */

palStatus_t storage_kvstore_read(const char *item_name, uint8_t *buffer, size_t buffer_size, size_t *buffer_actual_size_out);

/*! \brief Direct write to internal KVstore used for entropy injection with non-TRNG.
 *
 * @param[out] buffer_actual_size_out Size of data actually read from KVStore.
 * @param[in] KVStore kv_key item name to be read.
 * @param[in] buffer The buffer to be written.
 * @param[in] buffer_size The size of the buffer given.
 *
 */

palStatus_t storage_kvstore_write(const char *item_name, const uint8_t *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif
#endif //_PAL_PLAT_RTOS_H
