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
#include "PlatIncludes.h"
#include "pal_BSP.h"
#include "mbed.h"

#ifndef TEST_K64F_BAUD_RATE
#define TEST_K64F_BAUD_RATE 115200
#endif

#ifndef TEST_MAIN_THREAD_STACK_SIZE
#define TEST_MAIN_THREAD_STACK_SIZE (1024*7)
#endif





extern int initSDcardAndFileSystem(void);

Serial pc(USBTX, USBRX);

#ifdef __cplusplus
extern "C" {
#endif


bool runProgram(testMain_t func, pal_args_t * args)
{
	Thread thread(osPriorityNormal, TEST_MAIN_THREAD_STACK_SIZE);
	thread.start(callback(func, args));
	wait(1); // to be on the safe side - sleep for 1sec
	bool result = (thread.join() == osOK);
	return result;
}

bspStatus_t initPlatform(void** outputContext)
{
    bspStatus_t bspStatus = BSP_SUCCESS;
    int err = 0;

    pc.baud(TEST_K64F_BAUD_RATE);

    err = initSDcardAndFileSystem();
    if (err < 0) {
        bspStatus = BSP_GENERIC_FAILURE;
        printf("BSP ERROR: failed to init SD card and filesystem \r\n");
    }

    if (BSP_SUCCESS == bspStatus)
    {
        if (NULL != outputContext)
        {
            *outputContext = palTestGetNetWorkInterfaceContext();
        }
    }

    return bspStatus;
}

#ifdef __cplusplus
}
#endif
