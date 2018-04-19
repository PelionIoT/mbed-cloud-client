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
//uncomment this to use littleFS instead of fatFS
//#define PAL_EXAMPLE_USE_LITTLE_FS

#include "pal.h"
#include "mbed.h"
#include "BlockDevice.h"
#include "MBRBlockDevice.h"
#include "storage-selector/storage-selector.h"

bool FileSystemInit = false;

#ifndef PRIMARY_PARTITION_NUMBER
#define PRIMARY_PARTITION_NUMBER 1
#endif

#ifndef PRIMARY_PARTITION_START
#define PRIMARY_PARTITION_START 0
#endif

#ifndef PRIMARY_PARTITION_SIZE
#define PRIMARY_PARTITION_SIZE 512*1024
#endif

#ifndef SECONDARY_PARTITION_NUMBER
#define SECONDARY_PARTITION_NUMBER 2
#endif

#ifndef SECONDARY_PARTITION_START
#define SECONDARY_PARTITION_START PRIMARY_PARTITION_SIZE
#endif

#ifndef SECONDARY_PARTITION_SIZE
#define SECONDARY_PARTITION_SIZE PRIMARY_PARTITION_SIZE
#endif

//Uncomment this to create the partitions
#define PAL_EXAMPLE_GENERATE_PARTITION

//Uncomment this to format partitions if fs->mount() fails
#define PAL_EXAMPLE_FORMAT_PARTITION

#define PAL_PARTITION_TYPE 0x83
//
// See the mbed_lib.json in the sd-driver library for the definitions.
// See the sd-driver library README.md for details with CI-shield etc.
// Add also new boards/exceptions there rather than in code directly
// OR
// alternatively overload via your mbed_app.json (MBED_CONF_APP...)
//

static BlockDevice *bd = storage_selector();

static MBRBlockDevice part1(bd, 1);
static FileSystem  *fs1;
static MBRBlockDevice part2(bd, 2);
static FileSystem  *fs2;


static int ReFormatPartition(BlockDevice* part, FileSystem* filesystem)
{
	int err = 0;
	printf("re-format partition\r\n");
	err = filesystem->reformat(part);
	return err;
}

static int initFileSystem(BlockDevice* part, FileSystem* filesystem, bool reformat)
{
	int err = 0;
	if (reformat)
	{
		err = filesystem->reformat(part);
	}
	err = filesystem->unmount(); // filesystem_selector func do mount but doesnt return value , for checking if mount function return error we need first to unmount and then try to mount again.
	if (err < 0) {
		printf("failed to unmount %d\r\n", err);
	}
	err = filesystem->mount(part);
	if (err < 0) {
		printf("failed to mount %d\r\n", err);
		err = ReFormatPartition(part, filesystem);
	}
	if (err == 0) {
		err = filesystem->mkdir("bsp_test", 0600); // FATFS miss magic field. mkdir to check FS correctness.
		if (err != 0) {
			printf("failed to mkdir - reformat \r\n");
			err = ReFormatPartition(part, filesystem);
		}
		filesystem->remove("bsp_test"); // delete in any case even after format
	}
	return err;
}

int initSDcardAndFileSystem(bool reformat)
{
	int err = 0;
	printf("Initializing the file system\r\n");
#if (MBED_CONF_STORAGE_SELECTOR_FILESYSTEM_INSTANCES > 0)
		err = part1.init();
		if (err < 0)
		{
			printf("failed to init primary partition cause %d\r\n", err);
			err = MBRBlockDevice::partition(bd, PRIMARY_PARTITION_NUMBER, PAL_PARTITION_TYPE, PRIMARY_PARTITION_START, PRIMARY_PARTITION_START + PRIMARY_PARTITION_SIZE);
			if (err < 0) {
				printf("Failed to initialize primary partition\r\n");
			}
		}
		if (!err)
		{
			fs1 = filesystem_selector(((char*)PAL_FS_MOUNT_POINT_PRIMARY + 1), &part1, 1);
			err = initFileSystem(&part1, fs1, reformat);
		}
	#if (MBED_CONF_STORAGE_SELECTOR_FILESYSTEM_INSTANCES == 2)
				if (!err) {
					err = part2.init();
					if (err < 0) {
						printf("failed to init secondary partition cause %d\r\n", err);
						err = MBRBlockDevice::partition(bd, SECONDARY_PARTITION_NUMBER, PAL_PARTITION_TYPE, SECONDARY_PARTITION_START, SECONDARY_PARTITION_START + SECONDARY_PARTITION_SIZE);
						if (err < 0) {
							printf("Failed to initialize secondary partition\r\n");
						}
					}
					if (!err) {
						fs2 = filesystem_selector(((char*)PAL_FS_MOUNT_POINT_SECONDARY + 1), &part2, 2);
						err = initFileSystem(&part2, fs2, reformat);
					}
				}
	#endif
#endif
	if (!err)
	{
		printf("Succeed to initialize the file system\r\n");
		FileSystemInit = true;
	}

	return err;
}
