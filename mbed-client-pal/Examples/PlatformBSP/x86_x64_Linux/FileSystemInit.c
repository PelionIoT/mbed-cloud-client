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
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

bool FileSystemInit = true;

// Desktop Linux
// In order for tests to pass for all partition configurations we need to simulate the case of multiple
// partitions using a single folder. We do this by creating one or two different sub-folders, depending on
// the configuration.
int fileSystemCreateRootFolders(void)
{
	int status = 0;
	char folder[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};

	// Get default mount point.
	status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, folder);
	if(status != 0)
	{
	    return 1;
	}
	printf("Mount point for primary partition: %s\r\n",folder);
	// Make the sub-folder
	int res = mkdir(folder,0744);
    if(res)
    {
        // Ignore error if it exists
        if( errno != EEXIST)
        {
        	printf("mkdir failed errno= %d\r\n",errno);
            return 1;
        }
    }

    // Get default mount point.
    memset(folder,0,sizeof(folder));
    status = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, folder);
    printf("Mount point for secondary partition: %s\r\n",folder);
    if(status != 0)
    {
        return 1;
    }

    // Make the sub-folder
    res = mkdir(folder,0744);
    if(res)
    {
        // Ignore error if it exists
        if( errno != EEXIST)
        {
        	printf("mkdir failed errno= %d\r\n",errno);
            return 1;
        }
    }       
	return status;
}
