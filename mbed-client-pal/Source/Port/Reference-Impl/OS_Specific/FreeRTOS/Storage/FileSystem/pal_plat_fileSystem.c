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

#if ((!defined(PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM)) || (PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM == 0)) 
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal.h"
#include "pal_plat_fileSystem.h"
#include "pal_plat_rtos.h"


#if defined(__GNUC__) && !defined(__CC_ARM)
#include <sys/stat.h>
#include <sys/types.h>
#endif // defined(__GNUC__) && !defined(__CC_ARM)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fsl_mpu.h"
#include "ff.h"
#include "diskio.h"
#include "sdhc_config.h"


#define CHK_FD_VALIDITY(x) ((FIL *)x)->fs->id != ((FIL *)x)->id
#define PAL_FS_ALIGNMENT_TO_SIZE    4                                                          //!< This Size control the number of bytes written to the file (bug fix for writing unaligned memory to file)
#define PAL_FS_COPY_BUFFER_SIZE 256                                                            //!< Size of the chunk to copy files
PAL_PRIVATE BYTE g_platOpenModeConvert[] =
{
        0,
        FA_READ | FA_OPEN_EXISTING,                //"r"
        FA_WRITE | FA_READ| FA_OPEN_EXISTING,    //"r+"
        FA_WRITE | FA_READ| FA_CREATE_NEW,         //"w+x"
        FA_WRITE | FA_READ| FA_CREATE_ALWAYS    //"w+"
};    //!< platform convert table for \b fopen() modes


/*! \brief This function find the next file in a directory
 *
 * @param[in]    *dh - Directory handler to an open DIR
 * @param[out]    CurrentEntry - entry for the file found in Directory (pre allocated)
 *
 * \return true - upon successful operation.\n
 *
 */
PAL_PRIVATE bool pal_plat_findNextFile(DIR *dh, FILINFO  * CurrentEntry);

/*! \brief This function translate the platform errors opcode to pal error codes
 *
 * @param[in]    errorOpCode - platform opcode to be translated
 *
 * \return PAL_SUCCESS upon successful operation.\n
 */
PAL_PRIVATE palStatus_t pal_plat_errorTranslation (int errorOpCode);

/*! \brief This function build the full path name by adding the filename to the working path given in pathName arg
 *
 * @param[in]    *pathName - pointer to the null-terminated string that specifies the directory name.
 * @param[in]   *fileName - pointer to the file name
 * @param[out]    *fullPath - pointer to the full path including the filename (pre allocated)
 *
 * \return PAL_SUCCESS upon successful operation.\n
 *         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t
 *
 */
PAL_PRIVATE palStatus_t pal_plat_addFileNameToPath(const char *pathName, const char * fileName, char * fullPath);

/*! \brief This function copy one file from source folder to destination folder
 *
 * @param[in]  pathNameSrc - Pointer to a null-terminated string that specifies the source dir.
 * @param[in]  pathNameDest - Pointer to a null-terminated string that specifies the destination dir
 * @param[in] fileName - pointer the the file name
 *
 * \return PAL_SUCCESS upon successful operation.\n
 *         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t
 *
 * \note File should not be open.\n
 *         If the Destination file exist then it shall be truncated
 *
 */
PAL_PRIVATE palStatus_t pal_plat_fsCpFile(const char *pathNameSrc,  char *pathNameDest, char * fileName);

palStatus_t pal_plat_fsMkdir(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    status = f_mkdir(pathName);
    if (status != FR_OK)
    {
        ret = pal_plat_errorTranslation(status);
    }
    return ret;
}


palStatus_t pal_plat_fsRmdir(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;

    status = f_unlink(pathName);
    if (status != FR_OK)
    {
        if ( status == FR_DENIED)
        {
            ret = PAL_ERR_FS_DIR_NOT_EMPTY;
        }
        else if (status == FR_NO_FILE)
        {
            ret = PAL_ERR_FS_NO_PATH;
        }
        else
        {
            ret = pal_plat_errorTranslation(status);
        }
    }

    return ret;
}


palStatus_t pal_plat_fsFopen(const char *pathName, pal_fsFileMode_t mode, palFileDescriptor_t *fd)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    FIL * descriptor = NULL;

    descriptor = (FIL *)pal_plat_malloc(sizeof(FIL));
    if (descriptor)
    {
        *fd = (palFileDescriptor_t)descriptor;
        status = f_open((FIL*)*fd, pathName, g_platOpenModeConvert[mode]);
        if (FR_OK != status)
        {
            pal_plat_free(descriptor);
            if(FR_NO_PATH == status)
            {
                ret = PAL_ERR_FS_NO_FILE;
            }
            else
            {
                ret = pal_plat_errorTranslation(status);
            }
        }
    }

    return ret;
}


palStatus_t pal_plat_fsFclose(palFileDescriptor_t *fd)
{
    FRESULT status = FR_OK;
    palStatus_t ret = PAL_SUCCESS;


    if (CHK_FD_VALIDITY(*fd))
    {//Bad File Descriptor
        ret = PAL_ERR_FS_BAD_FD;
        return ret;
    }

    status = f_close((FIL *)*fd);
    if (FR_OK != status)
    {
        ret = pal_plat_errorTranslation(status);
    }
    else
    {
        pal_plat_free((void*)*fd);
    }
    return ret;
}


palStatus_t pal_plat_fsFread(palFileDescriptor_t *fd, void * buffer, size_t numOfBytes, size_t *numberOfBytesRead)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    uint8_t readaligment[PAL_FS_ALIGNMENT_TO_SIZE] = { 0 };
    uint32_t index = 0;
    size_t byteRead = 0;
    uint8_t  leftover = 0;

    if (CHK_FD_VALIDITY(*fd))
    {//Bad File Descriptor
        ret = PAL_ERR_FS_BAD_FD;
        return ret;
    }

    leftover = numOfBytes % PAL_FS_ALIGNMENT_TO_SIZE;
    for(index = 0; index < (numOfBytes / PAL_FS_ALIGNMENT_TO_SIZE); index++)
    {
        status = f_read((FIL *)*fd, readaligment, PAL_FS_ALIGNMENT_TO_SIZE, &byteRead);
        if (FR_OK != status)
        {
            ret = pal_plat_errorTranslation(status);
            break;
        }
        else
        {
            memcpy(&((uint8_t *)buffer)[*numberOfBytesRead], readaligment, PAL_FS_ALIGNMENT_TO_SIZE);
            *numberOfBytesRead += byteRead;
        }
    }

    if ((ret == PAL_SUCCESS) && (leftover > 0))
    {
        status = f_read((FIL *)*fd, readaligment, PAL_FS_ALIGNMENT_TO_SIZE, &byteRead);
        if (FR_OK != status)
        {
            ret = pal_plat_errorTranslation(status);
        }
        else
        {
            memcpy(&((uint8_t *)buffer)[*numberOfBytesRead], readaligment, leftover);
            *numberOfBytesRead += leftover;
            ret = pal_fsFseek(fd, leftover - PAL_FS_ALIGNMENT_TO_SIZE ,PAL_FS_OFFSET_SEEKCUR);
        }
    }

    return ret;
}


palStatus_t pal_plat_fsFwrite(palFileDescriptor_t *fd, const void *buffer, size_t numOfBytes, size_t *numberOfBytesWritten)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    uint32_t index = 0;
    size_t bytesWritten = 0;
    uint8_t  leftover = 0;

    if (CHK_FD_VALIDITY(*fd))
    {//Bad File Descriptor
        ret = PAL_ERR_FS_BAD_FD;
        return ret;
    }

    leftover = numOfBytes % PAL_FS_ALIGNMENT_TO_SIZE;
    for (index = 0; index < (numOfBytes / PAL_FS_ALIGNMENT_TO_SIZE); index++)
    {
        status = f_write((FIL *)*fd, ((uint8_t *)buffer + *numberOfBytesWritten), PAL_FS_ALIGNMENT_TO_SIZE, &bytesWritten);
        if (FR_OK != status)
        {
            ret = pal_plat_errorTranslation(status);
            break;
        }
        else if (PAL_FS_ALIGNMENT_TO_SIZE != bytesWritten)
        {
            ret = PAL_ERR_FS_INSUFFICIENT_SPACE;
        }
        else
        {
            *numberOfBytesWritten += bytesWritten;
        }
    }

    if ((ret == PAL_SUCCESS) && (leftover > 0))
    {
        status = f_write((FIL *)*fd, ((uint8_t *)buffer + *numberOfBytesWritten), leftover, &bytesWritten);
        if (FR_OK != status)
        {
            ret = pal_plat_errorTranslation(status);
        }
        else if (leftover != bytesWritten)
        {
            ret = PAL_ERR_FS_INSUFFICIENT_SPACE;
        }
        else
        {
            *numberOfBytesWritten += bytesWritten;
        }
    }

    return ret;
}


palStatus_t pal_plat_fsFseek(palFileDescriptor_t *fd, off_t offset, pal_fsOffset_t whence)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    size_t  fatFSOffset = 0;

    if (CHK_FD_VALIDITY(*fd))
    {//Bad File Descriptor
        ret = PAL_ERR_FS_BAD_FD;
        return ret;
    }


    switch(whence)
    {
    case PAL_FS_OFFSET_SEEKCUR:
        if (((-1)*offset  > f_tell((FIL*)*fd) && (offset < 0)) || (offset  > f_tell((FIL*)*fd) && (offset > 0)))
        {
            ret = PAL_ERR_FS_ERROR;
        }
        else
        {
            fatFSOffset = f_tell((FIL*)*fd) + offset;
        }
        break;

    case PAL_FS_OFFSET_SEEKEND:
        if ((-1)*offset  > f_size((FIL*)*fd) || (offset > 0))
        {
            ret = PAL_ERR_FS_ERROR;
        }
        else
        {
            fatFSOffset = f_size((FIL*)*fd) + offset;
        }
        break;

    case PAL_FS_OFFSET_SEEKSET:
        if (offset >  f_size((FIL*)*fd))
        {
            ret = PAL_ERR_FS_ERROR;
        }
        else
        {
            fatFSOffset = offset;
        }
        break;

    default:
        fatFSOffset = 0;
        break;
    }

    if (ret == PAL_SUCCESS)
    {
        status = f_lseek ((FIL *)*fd, fatFSOffset);
        if (FR_OK != status)
        {
            ret = pal_plat_errorTranslation(status);
        }
    }
    return ret;
}


palStatus_t pal_plat_fsFtell(palFileDescriptor_t *fd, off_t * pos)
{
    palStatus_t ret = PAL_SUCCESS;

    if (CHK_FD_VALIDITY(*fd))
    {//Bad File Descriptor
        ret = PAL_ERR_FS_BAD_FD;
    }
    else
    {
        *pos = f_tell((FIL*)*fd);
    }
    return ret;
}


palStatus_t pal_plat_fsUnlink(const char *pathName)
{
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;

    status = f_unlink(pathName);
    if (status != FR_OK)
    {
        if (status == FR_DENIED)
        {
            ret = PAL_ERR_FS_DIR_NOT_EMPTY;
        }
        else
        {
            ret = pal_plat_errorTranslation(status);
        }
    }
    return ret;
}


palStatus_t pal_plat_fsRmFiles(const char *pathName)
{
    DIR dh; //Directory handler
    palStatus_t ret = PAL_SUCCESS;
    FRESULT status = FR_OK;
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0}; //Buffer for coping the name and folder
    FILINFO  currentEntry = { 0 }; //file Entry

    status = f_opendir(&dh, pathName);
    if (status != FR_OK)
    {
        ret = pal_plat_errorTranslation(status);
    }

    if (ret == PAL_SUCCESS)
    {
        while(true)
        {
            if (!pal_plat_findNextFile(&dh, &currentEntry))
            {
                ret = PAL_ERR_FS_ERROR_IN_SEARCHING;
                break;
            }
            pal_plat_addFileNameToPath(pathName, currentEntry.fname, buffer);
            if (currentEntry.fname[0] != '\0')
            {
                if (currentEntry.fattrib & AM_DIR)
                {
                    ret = pal_fsRmFiles(buffer);
                    if (ret != PAL_SUCCESS)
                    {
                        break;
                    }
                    ret = pal_fsRmDir(buffer);
                    if (PAL_SUCCESS != ret)
                    {
                        break;
                    }
                }
                else
                {
                    status = f_unlink (buffer);
                    if (status != FR_OK)
                    {
                        ret = pal_plat_errorTranslation(status);
                        break;
                    }
                }
            }
            else
            {//End of directory reached  without errors break, close directory and exit
                break;
            }
        }//while()

        status = f_closedir (&dh); //Close DIR handler
        if (status != FR_OK)
        {
            ret = pal_plat_errorTranslation(status);
        }
    }

    return ret;
}


palStatus_t pal_plat_fsCpFolder(const char *pathNameSrc,  char *pathNameDest)
{
    DIR src_dh; //Directory for the source Directory handler
    palStatus_t ret = PAL_SUCCESS;
    FILINFO currentEntry = { 0 }; //file Entry
    FRESULT status = FR_OK;


    status = f_opendir(&src_dh, pathNameSrc);
    if (status != FR_OK)
    {
        ret = pal_plat_errorTranslation(status);
    }


    if (ret == PAL_SUCCESS)
    {
        while(true)
        {
            if (!pal_plat_findNextFile(&src_dh, &currentEntry))
            {
                ret = PAL_ERR_FS_ERROR_IN_SEARCHING;
                break;
            }
            if (currentEntry.fname[0] != 0)
            {
                if (currentEntry.fattrib & AM_DIR) // skip all folder as this is flat copy only
                {
                    continue;
                }
                //copy the file to the destination
                ret = pal_plat_fsCpFile(pathNameSrc, pathNameDest, currentEntry.fname);
                if (ret != PAL_SUCCESS)
                {
                    break;
                }
            }
            else
            {//End of directory reached  without errors break and close directory and exit
                break;
            }
        }//while()
        f_closedir(&src_dh);
    }

    return ret;
}


PAL_PRIVATE palStatus_t pal_plat_fsCpFile(const char *pathNameSrc,  char *pathNameDest, char * fileName)
{
    palStatus_t ret = PAL_SUCCESS;
    FIL src_fd, dst_fd;
    char * buffer = NULL;
    char buffer_name[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0}; //Buffer for coping the name and folder
    size_t bytesCount = 0;
    FRESULT status = FR_OK;

    //Add file name to path
    pal_plat_addFileNameToPath(pathNameSrc, fileName, buffer_name);
    status = f_open(&src_fd, buffer_name, g_platOpenModeConvert[PAL_FS_FLAG_READONLY]);
    if (status != FR_OK)
    {
        ret = pal_plat_errorTranslation(status);
    }
    else
    {
        //Add file name to path
        pal_plat_addFileNameToPath(pathNameDest, fileName, buffer_name);
        status = f_open(&dst_fd, buffer_name, g_platOpenModeConvert[PAL_FS_FLAG_READWRITETRUNC]);
        if (status != FR_OK)
        {
            ret = pal_plat_errorTranslation(status);
        }
        else
        {
            buffer = (char*)pal_plat_malloc(PAL_FS_COPY_BUFFER_SIZE);
            if (!buffer)
            {
                ret = PAL_ERR_RTOS_RESOURCE;
            }
        }
    }

    if (ret == PAL_SUCCESS)
    {
        while (1)
        {
            status = f_read(&src_fd, buffer, PAL_FS_COPY_BUFFER_SIZE, &bytesCount);

            if (status != FR_OK)
            {
                break;
            }

            //Check if end of file reached
            if (bytesCount == 0)
            {
                break;
            }

            status = f_write(&dst_fd, buffer, bytesCount, &bytesCount);
            if (status != FR_OK)
            {
                break;
            }
        }
        if (status != FR_OK)
        {
            ret = pal_plat_errorTranslation(status);
        }
    }



    f_close(&src_fd);
    f_close(&dst_fd);
    if (buffer)
    {
        pal_plat_free(buffer);
    }
    return ret;
}

const char* pal_plat_fsGetDefaultRootFolder(pal_fsStorageID_t dataID)
{
    const char* returnedRoot = NULL;
    if (PAL_FS_PARTITION_PRIMARY == dataID)
    {
        returnedRoot =  PAL_FS_MOUNT_POINT_PRIMARY;
    }
    else if (PAL_FS_PARTITION_SECONDARY == dataID)
    {
        returnedRoot =  PAL_FS_MOUNT_POINT_SECONDARY;
    }
    return returnedRoot;
}


PAL_PRIVATE bool pal_plat_findNextFile(DIR *dh, FILINFO  *CurrentEntry)
{
    bool ret = true;
    bool skip = false;
    bool foundFile = false;
    FRESULT status;

    do
    {
        status = f_readdir(dh, CurrentEntry);
        if (status == FR_OK)
        {
            if ((CurrentEntry)->fname[0] == 0)
            {//End Of Directory
                ret = true;
                break;
            }

            /* Skip the names "." and ".." as we don't want to remove them. also make sure that the current entry point to REGULER file*/
            skip = (!strcmp((CurrentEntry)->fname, ".")) || (!strcmp((CurrentEntry)->fname, ".."));
            if (skip)
            {
                continue;
            }
            else
            {
                foundFile = true;
            }
        }
        else
        {//NOT!!! EOF  other error
            ret = false;
            break; //Break from while
        }
    }
    while((!foundFile) && (ret)); //While file has been found or ret is set to false
    return ret;
}

PAL_PRIVATE palStatus_t pal_plat_addFileNameToPath(const char *pathName, const char * fileName, char * fullPath)
{
    palStatus_t ret = PAL_SUCCESS;

    if ((strlen(pathName) >= PAL_MAX_FOLDER_DEPTH_CHAR)  || (strlen(fileName) >= PAL_MAX_FULL_FILE_NAME))
    {
        ret = PAL_ERR_FS_FILENAME_LENGTH;
    }
    else if (fullPath)
    {
        strcpy(fullPath, pathName);
        strcat(fullPath, "/");
        strcat(fullPath, fileName);
    }
    else
    {
        ret = PAL_ERR_RTOS_RESOURCE;
    }
    return ret;
}


PAL_PRIVATE palStatus_t pal_plat_errorTranslation (int errorOpCode)
{
    palStatus_t ret = PAL_SUCCESS;

    switch(errorOpCode)
    {
    case 0:
        break;
    case FR_DENIED:
    case FR_WRITE_PROTECTED:
    case FR_LOCKED:
        ret = PAL_ERR_FS_ACCESS_DENIED;
        break;

    case FR_NOT_READY :
        ret = PAL_ERR_FS_BUSY;
        break;

    case FR_EXIST:
        ret = PAL_ERR_FS_NAME_ALREADY_EXIST;
        break;

    case FR_INVALID_NAME:
    case FR_INVALID_OBJECT:
    case FR_INVALID_DRIVE:
        ret = PAL_ERR_FS_INVALID_ARGUMENT;
        break;

    case  FR_NO_FILE:
        ret = PAL_ERR_FS_NO_FILE;
        break;

    case FR_NO_PATH:
        ret = PAL_ERR_FS_NO_PATH;
        break;

    default:
        ret = PAL_ERR_FS_ERROR;
        break;
    }
    return ret;
}


size_t pal_plat_fsSizeCheck(const char *stringToChk)
{
    size_t length = 0;
    length = strlen(stringToChk);
    return length;
}



palStatus_t pal_plat_fsFormat(pal_fsStorageID_t dataID)
{
	const char* partitionNames[] ={
                                    PAL_FS_MOUNT_POINT_PRIMARY,
                                    PAL_FS_MOUNT_POINT_SECONDARY
	                               };
    palStatus_t result = PAL_SUCCESS;
    const char* partName = partitionNames[dataID];
    FRESULT res = f_mkfs(partName, 0, 0);
    if (FR_OK != res)
    {
        result = PAL_ERR_FS_ERROR;
    }
    return result;
}
#endif
#endif
