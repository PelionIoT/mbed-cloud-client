/*******************************************************************************
* Copyright 2019 ARM Ltd.
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


#ifndef _PAL_ENTROPY_H
#define _PAL_ENTROPY_H

#ifndef _PAL_H
#error "Please do not include this file directly, use pal.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** \file pal_entropy.h
 *  \brief PAL entropy.
 *   This file contains entropy injection and is part of the PAL API.
 */

/** \brief Inject entropy to non-volatile memory, so that the random number generator may use it.
 *
 * In addition to OS functions, the module implementing `pal_drbg.h` will hold a deterministic
 * random bit generator (DRBG) instance that works with the entropy injected by this function.
 *
 * \note This API call must be placed before any function that may attempt to generate a
 * random number, both by the OS or PAL DRBG. After this API call,
 * `pal_osRandomBuffer()`` calls from `pal_drbg.h` will succeed.
 *
 * @param entropyBuf - pointer to buffer containing the entropy.
 * @param bufSizeBytes - size of `entropyBuf` in bytes.
 *
 * @return PAL_SUCCESS - if operation is successful
 * @return PAL_ERR_NOT_SUPPORTED - code compiled in a way that does not expect entropy to be injected. TRNG must be available to inject entropy.
 * @return PAL_ERR_INVALID_ARGUMENT - `bufSizeBytes` too small.
 * @return PAL_ERR_ENTROPY_EXISTS - Entropy already injected.
 * @return PAL_ERR_GENERIC_FAILURE - Another cause of error.
 */
palStatus_t pal_osEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes);

#ifdef __cplusplus
}
#endif
#endif // _PAL_ENTROPY_H
