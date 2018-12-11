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
#include "pal_time.h"
#include "pal_plat_time.h"

#define TRACE_GROUP "PAL"


palStatus_t pal_initTime(void)
{
    palStatus_t status;
    status = pal_plat_initTime();
    return status;
}

uint64_t pal_osGetTime(void)
{
    palStatus_t status;
    status = pal_plat_osGetTime();
    return status;
}

palStatus_t pal_osSetTime(uint64_t seconds)
{
    palStatus_t status;
    status = pal_plat_osSetTime(seconds);
    return status;
}

palStatus_t pal_osSetStrongTime(uint64_t setNewTimeInSeconds)
{
    palStatus_t status;
    status = pal_plat_osSetStrongTime(setNewTimeInSeconds);
    return status;
}

palStatus_t pal_osSetWeakTime(uint64_t setNewTimeInSeconds)
{
    palStatus_t status;
    status = pal_plat_osSetWeakTime(setNewTimeInSeconds);
    return status;
}

