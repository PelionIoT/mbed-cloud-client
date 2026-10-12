/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <bcrypt.h>
#include "pal_plat_entropy.h"
#include "pal_plat_drbg.h"

palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *buffer, size_t size, size_t *actual)
{
    size_t done = 0;
    if (actual) *actual = 0;
    if (!buffer && size) return PAL_ERR_INVALID_ARGUMENT;
    while (done < size) {
        ULONG chunk = (size - done > ULONG_MAX) ? ULONG_MAX : (ULONG)(size - done);
        if (BCryptGenRandom(NULL, buffer + done, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            if (actual) *actual = done;
            return PAL_ERR_RTOS_TRNG_FAILED;
        }
        done += chunk;
    }
    if (actual) *actual = done;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osRandomBuffer(uint8_t *buffer, size_t size, size_t *actual)
{
    /* SOTP's DRBG seed path uses this OS hook, as it does on Linux. */
    return pal_plat_getRandomBufferFromHW(buffer, size, actual);
}
