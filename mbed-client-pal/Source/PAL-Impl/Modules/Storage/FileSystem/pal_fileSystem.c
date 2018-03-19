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
/*
 * 2.c
 *
 *  Created on: 22 Jan 2017
 *      Author: alonof01
 */

#include "pal.h"
#include "pal_fileSystem.h"
#include "pal_plat_fileSystem.h"

PAL_PRIVATE char* g_RootFolder[PAL_FS_PARTITION_LAST] = { NULL , NULL };      //!< global var that holds the  root folder
PAL_PRIVATE bool g_RootFolderIsSet[PAL_FS_PARTITION_LAST] = { false, false };    //!< global var that holds the state root folder


void pal_fsCleanup()
{
    if (NULL != g_RootFolder[PAL_FS_PARTITION_PRIMARY])
    {
        free(g_RootFolder[PAL_FS_PARTITION_PRIMARY]);
        g_RootFolder[PAL_FS_PARTITION_PRIMARY] = NULL;
    }

    if (NULL != g_RootFolder[PAL_FS_PARTITION_SECONDARY])
    {
        free(g_RootFolder[PAL_FS_PARTITION_SECONDARY]);
        g_RootFolder[PAL_FS_PARTITION_SECONDARY] = NULL;
    }

    g_RootFolder[PAL_FS_PARTITION_SECONDARY] = NULL;
    g_RootFolderIsSet[PAL_FS_PARTITION_PRIMARY] = false;
    g_RootFolderIsSet[PAL_FS_PARTITION_SECONDARY] = false;
}



palStatus_t pal_fsMkDir(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((pathName == NULL), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(pathName) >= PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_FILENAME_LENGTH)

	ret = pal_plat_fsMkdir(pathName);
	if ((PAL_SUCCESS != ret) && (PAL_ERR_FS_NAME_ALREADY_EXIST != ret))
	{
		PAL_LOG(ERR, "Failed to create folder, was the storage properly initialized?");
	}

    return ret;
}



palStatus_t pal_fsRmDir(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((pathName == NULL), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(pathName) >= PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_FILENAME_LENGTH)

    ret = pal_plat_fsRmdir(pathName);
    return ret;
}

palStatus_t pal_fsFopen(const char *pathName, pal_fsFileMode_t mode, palFileDescriptor_t *fd)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR((fd == NULL), PAL_ERR_FS_INVALID_ARGUMENT)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pathName == NULL), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(pathName) >= PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_FILENAME_LENGTH)
	PAL_VALIDATE_CONDITION_WITH_ERROR((!((mode > PAL_FS_FLAG_KEEP_FIRST) && (mode < PAL_FS_FLAG_KEEP_LAST))), PAL_ERR_FS_INVALID_OPEN_FLAGS)

    ret = pal_plat_fsFopen(pathName,  mode, fd);
    if (ret != PAL_SUCCESS)
    {
        *fd = 0;
    }
    return ret;
}


palStatus_t pal_fsFclose(palFileDescriptor_t *fd)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((fd == NULL), PAL_ERR_FS_INVALID_ARGUMENT)
    PAL_VALIDATE_CONDITION_WITH_ERROR((*fd == 0), PAL_ERR_FS_BAD_FD)

	ret = pal_plat_fsFclose(fd);
	*fd = 0;
    return ret;
}


palStatus_t pal_fsFread(palFileDescriptor_t *fd, void * buffer, size_t numOfBytes, size_t *numberOfBytesRead)
{
    palStatus_t ret = PAL_SUCCESS;
    *numberOfBytesRead = 0;
    PAL_VALIDATE_CONDITION_WITH_ERROR((*fd == 0), PAL_ERR_FS_BAD_FD)
    PAL_VALIDATE_CONDITION_WITH_ERROR((buffer == NULL), PAL_ERR_FS_BUFFER_ERROR)

    ret = pal_plat_fsFread(fd, buffer, numOfBytes, numberOfBytesRead);
    return ret;
}


palStatus_t pal_fsFwrite(palFileDescriptor_t *fd, const void * buffer, size_t numOfBytes, size_t *numberOfBytesWritten)
{
    palStatus_t ret = PAL_SUCCESS;
    *numberOfBytesWritten = 0;
    PAL_VALIDATE_CONDITION_WITH_ERROR((*fd == 0), PAL_ERR_FS_BAD_FD)
    PAL_VALIDATE_CONDITION_WITH_ERROR((numOfBytes == 0), PAL_ERR_FS_LENGTH_ERROR)
    PAL_VALIDATE_CONDITION_WITH_ERROR((buffer == NULL), PAL_ERR_FS_BUFFER_ERROR)

    ret = pal_plat_fsFwrite(fd, buffer, numOfBytes, numberOfBytesWritten);
    return ret;
}


palStatus_t pal_fsFseek(palFileDescriptor_t *fd, int32_t offset, pal_fsOffset_t whence)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((*fd == 0), PAL_ERR_FS_BAD_FD)
    PAL_VALIDATE_CONDITION_WITH_ERROR((!((whence < PAL_FS_OFFSET_KEEP_LAST) && (whence > PAL_FS_OFFSET_KEEP_FIRST))), PAL_ERR_FS_OFFSET_ERROR)

    ret = pal_plat_fsFseek(fd, offset, whence);
    return ret;
}


palStatus_t pal_fsFtell(palFileDescriptor_t *fd, int32_t *pos)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((*fd == 0), PAL_ERR_FS_BAD_FD)

    ret = pal_plat_fsFtell(fd, pos);
    return ret;
}

palStatus_t pal_fsUnlink(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((pathName == NULL), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(pathName) >= PAL_MAX_FULL_FILE_NAME), PAL_ERR_FS_FILENAME_LENGTH)

    ret = pal_plat_fsUnlink(pathName);
    return ret;
}



palStatus_t pal_fsRmFiles(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((pathName == NULL), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(pathName) >= PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_FILENAME_LENGTH)

	ret = pal_plat_fsRmFiles(pathName);
    return ret;
}


palStatus_t pal_fsCpFolder(const char *pathNameSrc,  char *pathNameDest)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR(((pathNameSrc == NULL) || ((pathNameDest == NULL))), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR(((pal_plat_fsSizeCheck(pathNameSrc) >= PAL_MAX_FOLDER_DEPTH_CHAR) || (pal_plat_fsSizeCheck(pathNameDest) >= PAL_MAX_FOLDER_DEPTH_CHAR)), PAL_ERR_FS_FILENAME_LENGTH)

	ret = pal_plat_fsCpFolder(pathNameSrc, pathNameDest);
    return ret;
}



palStatus_t pal_fsSetMountPoint(pal_fsStorageID_t dataID, const char *path)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR(((dataID >= PAL_FS_PARTITION_LAST) || (NULL == path)), PAL_ERR_FS_INVALID_FILE_NAME)
    PAL_VALIDATE_CONDITION_WITH_ERROR((pal_plat_fsSizeCheck(path) >= PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_FILENAME_LENGTH)

	if (g_RootFolderIsSet[dataID])
	{
		ret = PAL_ERR_FS_ERROR;
	}
	else
	{
		if (NULL == g_RootFolder[dataID])
		{
			g_RootFolder[dataID] = (char*)malloc(PAL_MAX_FOLDER_DEPTH_CHAR);
			if (NULL == g_RootFolder[dataID])
			{
				return PAL_ERR_NO_MEMORY;
			}
			g_RootFolder[dataID][0] = NULLPTR;
		}
		strncat( g_RootFolder[dataID], path, PAL_MAX_FOLDER_DEPTH_CHAR - pal_plat_fsSizeCheck(g_RootFolder[dataID]));// same buffer is used for active backup root dirs using indexing
		g_RootFolderIsSet[dataID] = true;
	}
    return ret;
}

palStatus_t pal_fsGetMountPoint(pal_fsStorageID_t dataID, size_t length, char *path)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR((dataID >= PAL_FS_PARTITION_LAST), PAL_ERR_INVALID_ARGUMENT)
    PAL_VALIDATE_CONDITION_WITH_ERROR((length < PAL_MAX_FOLDER_DEPTH_CHAR), PAL_ERR_FS_LENGTH_ERROR)

    if (path)
    {
        if (false == g_RootFolderIsSet[dataID])
        {
            strncpy(path, pal_plat_fsGetDefaultRootFolder(dataID), length);
        }
        else 
        {
            strncpy(path, g_RootFolder[dataID], length); // same buffer is used for active backup root dirs using indexing
        }
        
    }
    else
    {
        ret = PAL_ERR_FS_BUFFER_ERROR;
    }
    return ret;
}


palStatus_t pal_fsFormat(pal_fsStorageID_t dataID)
{
    palStatus_t ret = PAL_SUCCESS;
    PAL_VALIDATE_CONDITION_WITH_ERROR((((int32_t)dataID < PAL_FS_PARTITION_PRIMARY) || ((int32_t)dataID >= PAL_FS_PARTITION_LAST)), PAL_ERR_INVALID_ARGUMENT)

#if PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT //Simulator    
	char rootFolder[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
	ret = pal_fsGetMountPoint(dataID, PAL_MAX_FILE_AND_FOLDER_LENGTH, rootFolder);
	if (PAL_SUCCESS == ret)
	{
		ret = pal_plat_fsRmFiles(rootFolder);
		if (PAL_SUCCESS != ret)
		{
			PAL_LOG(ERR,"(%s:%d) pal_plat_fsRmFiles  failed ",__FILE__,__LINE__);
		}
	}
#else //Real life scenario
	ret = pal_plat_fsFormat(dataID);
#endif        
    
    return ret;
}




bool pal_fsIsPrivatePartition(pal_fsStorageID_t dataID)
{
    bool isPrivate;
    if (PAL_FS_PARTITION_PRIMARY == dataID)
    {
        isPrivate = PAL_PRIMARY_PARTITION_PRIVATE;
    }
    else
    {
        isPrivate = PAL_SECONDARY_PARTITION_PRIVATE;
    }
    return isPrivate;
}
