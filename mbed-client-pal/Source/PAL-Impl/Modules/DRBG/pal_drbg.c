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

#include "pal.h"
#include "pal_plat_drbg.h"


palStatus_t pal_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes)
{
    return pal_plat_osRandomBuffer_blocking(randomBuf, bufSizeBytes);
}

// a simple wrapper, no need to keep it on platform layer. This uses also direct
// call to pal_plat_osRandomBuffer() in order to let linker to remove as many unused
// as possible.
palStatus_t pal_osRandom32bit(uint32_t *randomInt)
{
    palStatus_t status;
    status = pal_plat_osRandomBuffer_blocking((uint8_t*)randomInt, sizeof(uint32_t));
    return status;
}


