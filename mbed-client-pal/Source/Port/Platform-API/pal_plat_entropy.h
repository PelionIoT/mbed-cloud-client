/*******************************************************************************
* Copyright 2016-2021 Pelion.
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


#ifndef _PAL_PLAT_ENTROPY_H
#define _PAL_PLAT_ENTROPY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"
#include "pal_entropy.h"
#include <stdint.h>

/** \file pal_plat_entropy.h
 *  \brief PAL entropy - platform.
 *   This file contains entropy injection as part of the platform layer.
 */

//! The maximum entropy size that may be injected to non-volatile memory
#define PAL_PLAT_MAX_ENTROPY_SIZE 48

/** \brief Inject entropy to non-volatile memory, so that the random number generator may use it.
 *
 * In addition to OS functions, the module implementing `pal_plat_drbg.h` will hold a deterministic
 * random bit generator (DRBG) instance that works with the entropy injected by this function.
 *
 * Note: This API call must be placed prior to any function that may attempt to generate a
 * random number, both by the OS or PAL platform DRBG. After this API call,
 * `pal_plat_osRandomBuffer_blocking()` calls from `pal_plat_drbg.h` will succeed.
 *
 * @param entropyBuf - pointer to buffer containing the entropy.
 * @param bufSizeBytes - size of `entropyBuf` in bytes.
 *
 * @return PAL_SUCCESS - if operation is successful.
 * @return PAL_ERR_NOT_SUPPORTED - code compiled in a way that does not expect entropy to be injected. TRNG must be available to inject entropy.
 * @return PAL_ERR_INVALID_ARGUMENT - `bufSizeBytes` too small.
 * @return PAL_ERR_ENTROPY_EXISTS - Entropy already injected.
 * @return PAL_ERR_GENERIC_FAILURE - Another cause of error.
 */
palStatus_t pal_plat_osEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes);

/** \brief Read entropy from non-volatile memory.
*
* The function firstly reads the file name associated with `ENTROPYSOURCE` variable if exist in the target system environment,
* if not, it will explicitly take the `entropyFileName` given by the caller.
*
* @param entropyFileName - the default file name to read the entropy from in case system environment ENTROPYSOURCE is absent.
* @param randomBufOut - pointer to buffer which the entropy source will be written to.
* @param bufSizeBytes - size of `randomBufOut` in bytes.
* @param actualRandomSizeBytesOut - the actual size in bytes written to `randomBufOut`.
*
* @return PAL_SUCCESS - if operation is successful.
* @return PAL_ERR_RTOS_TRNG_FAILED - the entropy source is empty.
* @return PAL_ERR_FS_NO_FILE - The entropy source does not exist.
* @return PAL_ERR_RTOS_TRNG_PARTIAL_DATA - `bufSizeBytes` too small or too big.
*/
palStatus_t pal_plat_osEntropyRead(const char *entropyFileName, uint8_t *randomBufOut, size_t bufSizeBytes, size_t *actualRandomSizeBytesOut);

/**
 * Inject entropy to non-volatile memory.
 *
 * @param entropyBuf - pointer to buffer containing the entropy
 * @param bufSizeBytes - size of entropyBuf in bytes
 *
 * @return PAL_SUCCESS - if operation is successful
 *         PAL_ERR_ENTROPY_EXISTS - Entropy already injected
 *         PAL_ERR_GENERIC_FAILURE - any other case
 */

palStatus_t pal_plat_DRBGEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes);

#ifdef __cplusplus
}
#endif
#endif // _PAL_PLAT_ENTROPY_H
