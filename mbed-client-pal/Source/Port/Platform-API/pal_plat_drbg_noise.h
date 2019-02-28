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

#ifndef _PAL_PLAT_NOISE_H
#define _PAL_PLAT_NOISE_H
#include "pal.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// This file is internal and should not be ported by the user!

palStatus_t pal_plat_noiseInit(void);
palStatus_t pal_plat_noiseDestroy(void);
palStatus_t pal_plat_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten);
palStatus_t pal_plat_noiseCreateThread(void);
palStatus_t pal_plat_generateDrbgWithNoiseAttempt(palCtrDrbgCtxHandle_t drbgContext, uint8_t* outBuffer, bool partial, size_t numBytesToGenerate);

#ifdef __cplusplus
}
#endif

#endif // _PAL_PLAT_NOISE_H
