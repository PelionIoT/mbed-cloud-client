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
#include "pal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "fsl_mpu.h"
#include "ff.h"
#include "diskio.h"
#include "sdhc_config.h"
#include "fsl_debug_console.h"


//uncomment this to create the partitions
//#define PAL_EXAMPLE_GENERATE_PARTITION 1
//Uncomment this to allow format
//#define PAL_EXAMPLE_FORMAT_PARTITION 1

#if (PAL_NUMBER_OF_PARTITIONS > 0)

#ifndef _MULTI_PARTITION
#error "Please Define _MULTI_PARTITION in ffconf.h"
#endif

#if ((PAL_NUMBER_OF_PARTITIONS > 2) || (PAL_NUMBER_OF_PARTITIONS < 0))
#error "Pal partition number is not supported, please set to a number between 0 and 2"
#endif

PARTITION VolToPart[] = {
#if (PAL_NUMBER_OF_PARTITIONS > 0)
		{SDDISK,1}, /* 0: */
#endif
#if (PAL_NUMBER_OF_PARTITIONS > 1)
		{SDDISK,2}  /* 1: */
#endif
};
#endif

bool FileSystemInit = false;
#define MAX_SD_READ_RETRIES	5
#define LABEL_LENGTH	66
/*!
 * @brief Get event instance.
 * @param eventType The event type
 * @return The event instance's pointer.
 */
PAL_PRIVATE volatile uint32_t *EVENT_GetInstance(event_t eventType);

/*! @brief Transfer complete event. */
PAL_PRIVATE volatile uint32_t g_eventTransferComplete;

PAL_PRIVATE volatile uint32_t g_eventSDReady;

/*! @brief Time variable unites as milliseconds. */
PAL_PRIVATE volatile uint32_t g_timeMilliseconds;

/*! @brief Preallocated Work area (file system object) for logical drive, should NOT be free or lost*/
PAL_PRIVATE FATFS fileSystem[2];

/*! \brief CallBack function for SD card initialization
 *		   Set systick reload value to generate 1ms interrupt
 * @param void
 *
 * \return void
 *
 */
void EVENT_InitTimer(void)
{
	/* Set systick reload value to generate 1ms interrupt */
	SysTick_Config(CLOCK_GetFreq(kCLOCK_CoreSysClk) / 1000U);
}


/*! \brief CallBack function for SD card initialization
 *
 * @param void
 *
 * \return pointer to the requested instance
 *
 */
PAL_PRIVATE volatile uint32_t *EVENT_GetInstance(event_t eventType)
{
	volatile uint32_t *event;

	switch (eventType)
	{
	case kEVENT_TransferComplete:
		event = &g_eventTransferComplete;
		break;
	default:
		event = NULL;
		break;
	}

	return event;
}

/*! \brief CallBack function for SD card initialization
 *
 * @param event_t
 *
 * \return TRUE if instance was found
 *
 */
bool EVENT_Create(event_t eventType)
{
	volatile uint32_t *event = EVENT_GetInstance(eventType);

	if (event)
	{
		*event = 0;
		return true;
	}
	else
	{
		return false;
	}
}

/*! \brief blockDelay - Blocks the task and count the number of ticks given
 *
 * @param void
 *
 * \return TRUE - on success
 *
 */
void blockDelay(uint32_t Ticks)
{
	uint32_t tickCounts = 0;
	for(tickCounts = 0; tickCounts < Ticks; tickCounts++){}
}


/*! \brief CallBack function for SD card initialization
 *
 * @param void
 *
 * \return TRUE - on success
 *
 */
bool EVENT_Wait(event_t eventType, uint32_t timeoutMilliseconds)
{
	uint32_t startTime;
	uint32_t elapsedTime;

	volatile uint32_t *event = EVENT_GetInstance(eventType);

	if (timeoutMilliseconds && event)
	{
		startTime = g_timeMilliseconds;
		do
		{
			elapsedTime = (g_timeMilliseconds - startTime);
		} while ((*event == 0U) && (elapsedTime < timeoutMilliseconds));
		*event = 0U;

		return ((elapsedTime < timeoutMilliseconds) ? true : false);
	}
	else
	{
		return false;
	}
}

/*! \brief CallBack function for SD card initialization
 *
 * @param eventType
 *
 * \return TRUE if instance was found
 *
 */
bool EVENT_Notify(event_t eventType)
{
	volatile uint32_t *event = EVENT_GetInstance(eventType);

	if (event)
	{
		*event = 1U;
		return true;
	}
	else
	{
		return false;
	}
}

/*! \brief CallBack function for SD card initialization
 *
 * @param eventType
 *
 * \return void
 *
 */
void EVENT_Delete(event_t eventType)
{
	volatile uint32_t *event = EVENT_GetInstance(eventType);

	if (event)
	{
		*event = 0U;
	}
}




static int initPartition(pal_fsStorageID_t partitionId)
{
	char folderName[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
	FRESULT fatResult = FR_OK;
	int status = 0;

	status = pal_fsGetMountPoint(partitionId,PAL_MAX_FILE_AND_FOLDER_LENGTH,folderName);
	if (PAL_SUCCESS == status)
	{
		fatResult = f_mount(&fileSystem[partitionId], folderName, 1U);
		if (FR_OK != fatResult)
		{
#ifdef PAL_EXAMPLE_FORMAT_PARTITION
				PRINTF("Failed to mount partition %s in disk formating and trying again\r\n",folderName);
				fatResult = f_mkfs(folderName, 0, 0);
				if (FR_OK == fatResult)
				{
					fatResult = f_mount(&fileSystem[partitionId], folderName, 1U);
				}
#endif
			if (FR_OK != fatResult)
			{
				PRINTF("Failed to format & mount partition %s\r\n",folderName);
			}
		}
	}
	else
	{
		PRINTF("Failed to get mount point for partition %d\r\n",partitionId);
	}
	return status;
}

/*! \brief This function mount the fatfs on and SD card
 *
 * @param void
 *
 * \return palStatus_t - PAL_SUCCESS when mount point succeeded
 *
 */

void fileSystemMountDrive(void)
{
	PRINTF("%s : Creating FileSystem SetUp thread!\r\n",__FUNCTION__);
	int count = 0;
	int status = 0;

	if (FileSystemInit == false)
	{
		//Detected SD card inserted
		while (!(GPIO_ReadPinInput(BOARD_SDHC_CD_GPIO_BASE, BOARD_SDHC_CD_GPIO_PIN)))
		{
			blockDelay(1000U);
			if (count++ > MAX_SD_READ_RETRIES)
			{
				break;
			}
		}

		if(count < MAX_SD_READ_RETRIES)
		{
			/* Delay some time to make card stable. */
			blockDelay(10000000U);
#ifdef PAL_EXAMPLE_GENERATE_PARTITION
#if (PAL_NUMBER_OF_PARTITIONS == 1)
			DWORD plist[] = {100,0,0,0};
#elif	(PAL_NUMBER_OF_PARTITIONS == 2) //else of (PAL_NUMBER_OF_PARTITIONS == 1)
			DWORD plist[] = {50,50,0,0};
#endif //(PAL_NUMBER_OF_PARTITIONS == 1)
			BYTE work[_MAX_SS];

			status = f_fdisk(SDDISK,plist, work);
			PRINTF("f_fdisk fatResult=%d\r\n",status);
			if (FR_OK != status)
			{
				PRINTF("Failed to create partitions in disk\r\n");
			}
#endif //PAL_EXAMPLE_GENERATE_PARTITION


			status = initPartition(PAL_FS_PARTITION_PRIMARY);
#if (PAL_NUMBER_OF_PARTITIONS == 2)
			status = initPartition(PAL_FS_PARTITION_SECONDARY);
#endif


			if (!status) // status will be 0, if all passess
			{
				FileSystemInit = true;
				PRINTF("%s : Exit FileSystem SetUp thread!\r\n",__FUNCTION__);
			}
		}
	}
	vTaskDelete( NULL );
}
