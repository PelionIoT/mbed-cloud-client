/* SPDX-License-Identifier: Apache-2.0 */
#include <sys/random.h>
#include "pal_plat_entropy.h"
#include "pal_plat_drbg.h"

palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *buffer, size_t size, size_t *actual)
{
    size_t done = 0;
    if (actual) *actual = 0;
    if (!buffer && size) return PAL_ERR_INVALID_ARGUMENT;
    while (done < size) {
        size_t chunk = size - done > 256 ? 256 : size - done;
        if (getentropy(buffer + done, chunk) != 0) {
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
    return pal_plat_getRandomBufferFromHW(buffer, size, actual);
}
