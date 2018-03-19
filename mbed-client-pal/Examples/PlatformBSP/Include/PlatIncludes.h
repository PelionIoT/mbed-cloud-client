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
#ifndef K64_BSPINCLUDES_H_
#define K64_BSPINCLUDES_H_

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief This function initialized the network interface
*
* @param None
*
* \return void
*
*/
void networkInit(void *arg);

/*! \brief This function return the interface context
*
* @param None
*
* \return void *
*
*/
void* palTestGetNetWorkInterfaceContext(void);


/*! \brief This function initialized the Board interface
*
* @param None
*
* \return void
*
*/
void boardInit();


/*! \brief This function initialized the FileSystem interface
*
* @param None
*
* \return void
*
*/
void fileSystemMountDrive(void);

#ifdef PAL_MEMORY_STATISTICS
void printMemoryStats(void);
#define PRINT_MEMORY_STATS	printMemoryStats();
#else //PAL_MEMORY_STATISTICS
#define PRINT_MEMORY_STATS
#endif

#ifdef __cplusplus
}
#endif

#endif /* K64_BSPINCLUDES_H_ */
