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
#ifndef MBED_CLIENT_PAL_TEST_MAINTEST_H_
#define MBED_CLIENT_PAL_TEST_MAINTEST_H_



#ifdef PAL_LINUX
#define PAL_TEST_THREAD_STACK_SIZE 16*1024*sizeof(uint32_t)
#else
#define PAL_TEST_THREAD_STACK_SIZE 512*sizeof(uint32_t)
#endif
#include <stdbool.h>

typedef struct {
	int argc;
	char **argv;
} pal_args_t;


#ifdef __cplusplus
extern "C" {
#endif


typedef void (*testMain_t)(pal_args_t *);

typedef enum {
    //Success Codes are positive
    BSP_SUCCESS = 0,

    //All errors are Negative
    // generic errors
    BSP_GENERIC_FAILURE =  -1,
    BSP_PARAMETER_FAILURE =  -2,
    BSP_THREAD_CREATION_FAILURE =  -3,
    BSP_NETWORK_TIMEOUT =  -4,
    BSP_FILE_SYSTEM_TIMEOUT =  -5
} bspStatus_t; /*! errors returned by the pal BSP code */


/*! \brief This function initialized the platform (BSP , file system ....)
*
* @param[out] outputContext: used to return the network context to be used by the tests. The funciton expects the address of a writable void* in order to return this value (use NULL if not applicable).
*
* \return status of platform intialization
*
*/
bspStatus_t initPlatform(void** outputContext);


/*! \brief This function is called from the main function
*			and calls the startup sequence for the board tests
*
* @param[in] mainTestFunc - callback function for the main test runner
* @param[in] args - structure the contains argv and argc received from the main function
*
* \return void
*
*/
bool runProgram(testMain_t mainTestFunc, pal_args_t * args);



#ifdef __cplusplus
}
#endif

#endif /* MBED_CLIENT_PAL_TEST_MAINTEST_H_ */
