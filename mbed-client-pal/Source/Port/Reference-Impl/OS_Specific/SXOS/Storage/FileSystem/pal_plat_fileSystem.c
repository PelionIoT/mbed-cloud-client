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

#include "pal.h"
#include "pal_plat_fileSystem.h"

#include <vfs.h>
#include <sys/errno.h>

#define TRACE_GROUP "PAL"

#define PAL_FS_COPY_BUFFER_SIZE 1024  //!< Size of the chunk to copy files

#if 0
// This block is useful for validating code and determining if the error
// is given and handled correctly.
#include <stdio.h>
#define PLAT_FS_DEBUG(ARGS...) printf(ARGS)
#else
#define PLAT_FS_DEBUG(ARGS...)
#endif

// XXX: the errno is shared between all the threads and even with LwIP.
// I can't find code on scheduler to switch its value on task switch, so 
// this may therefore cause bad race conditions. This needs clarification
// with vendor. I just hope I'm wrong as usual.
extern int errno;

// XXX: why is this missing from vfs.h and it has local typedefs on every user.c?
typedef long off_t;

palStatus_t pal_plat_fsMkdir(const char *pathName)
{
    palStatus_t status = PAL_SUCCESS;

    // XXX: is this really used?!
    const int dir_mode = 0777;

    PLAT_FS_DEBUG("pal_plat_fsMkdir(%s)\n", pathName);

    int err = vfs_mkdir(pathName, dir_mode);

    if (err < 0)
    {
        PLAT_FS_DEBUG("pal_plat_fsMkdir(%s) failed: %d, errno: %d\n", pathName, err, errno);

        if (errno == EEXIST)
        {
            status = PAL_ERR_FS_NAME_ALREADY_EXIST;
        }
        else
        {
            status = PAL_ERR_FS_ERROR;
        }
    }

    return status;
}


palStatus_t pal_plat_fsRmdir(const char *pathName)
{
    palStatus_t status = PAL_SUCCESS;

    PLAT_FS_DEBUG("pal_plat_fsRmdir(%s)\n", pathName);

    int err = vfs_rmdir(pathName);

    if (err < 0)
    {
        switch (errno) {
            case ENOENT:
                status = PAL_ERR_FS_NO_PATH;
                break;
            case ENOTEMPTY:
                status = PAL_ERR_FS_DIR_NOT_EMPTY;
                break;
            default:
                status = PAL_ERR_FS_ERROR;
        }
    }

    return status;
}


palStatus_t pal_plat_fsFopen(const char *pathName, pal_fsFileMode_t mode, palFileDescriptor_t *fd)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs;
    bool useOpen = true;

    int flags;

    PLAT_FS_DEBUG("pal_plat_fsFopen(%s, %d)\n", pathName, (int)mode);

    switch (mode) {
        case PAL_FS_FLAG_READONLY:
            // Open file for reading. The stream is positioned at the beginning of the file (file must exist), same as "r".\n
            flags = O_RDONLY;
            break;

        case PAL_FS_FLAG_READWRITE:
            // Open for reading and writing. The stream is positioned at the beginning of the file (file must exist), same as "r+ ".\n
            flags = O_RDWR;
            break;
        case PAL_FS_FLAG_READWRITEEXCLUSIVE:
            // Open for reading and writing exclusively. If the file already exists, `fopen()` fails. The stream is positioned at the beginning of the file. same as "w+x"\n
            flags = O_RDWR | O_EXCL | O_CREAT;
            break;
        case PAL_FS_FLAG_READWRITETRUNC:
            // Open for reading and writing exclusively. If the file already exists, truncate file. The stream is positioned at the beginning of the file. same as "w+"\n
            flags = O_RDWR | O_EXCL | O_TRUNC;
            useOpen = false; // use vfs_create(), not vfs_open()
            break;
        default:
            status = PAL_ERR_FS_INVALID_OPEN_FLAGS;
            break;
    }

    if (PAL_SUCCESS == status)
    {
        if (useOpen)
        {
            fileOs = vfs_open(pathName, flags);
        }
        else
        {
            // is the flags really meaningful here at all? Actualy the
            // vfs_creat() is just a wrapper for vfs_open(), but I suppose
            // it is still safer to use the separate call.
            fileOs = vfs_creat(pathName, flags);
        }

        if (fileOs >= 0)
        {
            PLAT_FS_DEBUG("pal_plat_fsFopen(%s) succeeded, handle: %d\n", pathName, fileOs);

            *fd = fileOs;
        }
        else
        {
            PLAT_FS_DEBUG("pal_plat_fsFopen(%s) failed, ret: %d, errno: %d\n", pathName, fileOs, errno);

            // Some error happened. I can't find a documentation for error codes, but using posix codes
            // seems to be best bet. errno is there, but is it thread safe? I guess not, but we need to use what we have.
            switch (errno) {
                case ENOENT:
                    status = PAL_ERR_FS_NO_FILE;
                    break;
                case EEXIST:
                    status = PAL_ERR_FS_NAME_ALREADY_EXIST;
                    break;
                default:
                    status = PAL_ERR_FS_ERROR;
            }
        }
    }

    return status;
}


palStatus_t pal_plat_fsFclose(palFileDescriptor_t *fd)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs = *fd;

    PLAT_FS_DEBUG("pal_plat_fsFclose(%d)\n", fileOs);

    int err = vfs_close(fileOs);
    if (err < 0)
    {
        status = PAL_ERR_FS_ERROR;
    }
    else
    {
        *fd = -1;
    }

    return status;
}


palStatus_t pal_plat_fsFread(palFileDescriptor_t *fd, void * buffer, size_t numOfBytes, size_t *numberOfBytesRead)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs = *fd;

    ssize_t bytes_read = vfs_read(fileOs, buffer, numOfBytes);

    PLAT_FS_DEBUG("pal_plat_fsFread(%d), ret: %d, errno: %d\n", fileOs, (int)bytes_read, errno);

    if (bytes_read < 0)
    {
        *numberOfBytesRead = 0;
        status = PAL_ERR_FS_ERROR;
    }
    else
    {
        *numberOfBytesRead = (size_t)bytes_read;
    }

    return status;
}


palStatus_t pal_plat_fsFwrite(palFileDescriptor_t *fd, const void *buffer, size_t numOfBytes, size_t *numberOfBytesWritten)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs = *fd;

    ssize_t bytes_written = vfs_write(fileOs, buffer, numOfBytes);

    PLAT_FS_DEBUG("pal_plat_fsFwrite(%d), ret: %d, errno: %d\n", fileOs, (int)bytes_written, errno);

    if (bytes_written < 0)
    {
        *numberOfBytesWritten = 0;
        status = PAL_ERR_FS_ERROR;
    }
    else
    {
        *numberOfBytesWritten = (size_t)bytes_written;
    }

    return status;
}


palStatus_t pal_plat_fsFseek(palFileDescriptor_t *fd, int32_t offset, pal_fsOffset_t whence)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs = *fd;

    int mode;

    // TODO:
    // * check if the weird line in pal_plat_fsFseek/ "* In both options, \c fseek() needs to verify that the offset is smaller than the file end or start."
    //   really is even attempted somewhere.

    switch (whence) {
        case PAL_FS_OFFSET_SEEKSET:
            //!< Relative to the start of the file.
            mode = SEEK_SET;
            break;
        case PAL_FS_OFFSET_SEEKCUR:
            //!< The current position indicator.
            mode = SEEK_CUR;
            break;
        case PAL_FS_OFFSET_SEEKEND:
            //!< End-of-file.
            mode = SEEK_END;
            break;
        default:
            // the other values are actually checked at higher layer, but it will not
            // hurt here and it also keeps the Coverity silent.
            status = PAL_ERR_FS_OFFSET_ERROR;
    }

    if (PAL_SUCCESS == status)
    {
        off_t err = vfs_lseek(fileOs, offset, mode);

        if (err < 0)
        {
            PLAT_FS_DEBUG("pal_plat_fsFseek(%d, off: %d, wh: %d) failed, ret: %d, errno: %d\n", fileOs, (int)offset, (int)whence, (int)err, errno);
            status = PAL_ERR_FS_ERROR;
        }
        else
        {
            PLAT_FS_DEBUG("pal_plat_fsFseek(%d, off: %d, wh: %d) succeeded, ret: %d\n", fileOs, (int)offset, (int)whence, (int)err);
        }
    }

    return status;
}


palStatus_t pal_plat_fsFtell(palFileDescriptor_t *fd, int32_t *pos)
{
    palStatus_t status = PAL_SUCCESS;

    int fileOs = *fd;

    off_t err = vfs_lseek(fileOs, 0, SEEK_CUR);

    if (err < 0)
    {
        PLAT_FS_DEBUG("pal_plat_fsFtell(%d) failed, ret: %d, errno: %d\n", fileOs, (int)err, errno);
        status = PAL_ERR_FS_ERROR;
    }
    else
    {
        PLAT_FS_DEBUG("pal_plat_fsFtell(%d) succeeded, ret: %d\n", fileOs, (int)err);
        *pos = (int32_t)err;
    }

    return status;
}


palStatus_t pal_plat_fsUnlink(const char *pathName)
{
    palStatus_t status = PAL_SUCCESS;

    int err = vfs_unlink(pathName);

    if (err < 0)
    {
        PLAT_FS_DEBUG("pal_plat_fsUnlink(%s) failed, ret: %d, errno: %d\n", pathName, err, errno);
        if (errno == ENOENT)
        {
            status = PAL_ERR_FS_NO_FILE;
        }
        else
        {
            status = PAL_ERR_FS_ERROR;
        }
    }
    else
    {
        PLAT_FS_DEBUG("pal_plat_fsUnlink(%s) succeeded, ret: %d\n", pathName, (int)err);
    }
    return status;
}

// Note: the following functions are mostly shared with other OS' implementations,
// so the changes are kept in minimum and even the typos are the same.

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


PAL_PRIVATE palStatus_t pal_plat_fsCpFile(const char *pathNameSrc,  char *pathNameDest, char * fileName)
{
    palStatus_t ret = PAL_SUCCESS;
    palFileDescriptor_t src_fd = 0;
    palFileDescriptor_t dst_fd = 0;
    char buffer_name[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0}; //Buffer for coping the name and folder
    char * buffer = NULL;
    size_t bytesCount = 0;

    //Add file name to path
    pal_plat_addFileNameToPath(pathNameSrc, fileName, buffer_name);

    ret = pal_fsFopen(buffer_name, PAL_FS_FLAG_READONLY, &src_fd);

    if (ret == PAL_SUCCESS)
    {
        //Add file name to path
        pal_plat_addFileNameToPath(pathNameDest, fileName, buffer_name);

        ret = pal_fsFopen(buffer_name, PAL_FS_FLAG_READWRITETRUNC, &dst_fd);

        if (ret == PAL_SUCCESS)
        {
            buffer = (char*)malloc(PAL_FS_COPY_BUFFER_SIZE);
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
            ret = pal_fsFread(&src_fd, buffer, PAL_FS_COPY_BUFFER_SIZE, &bytesCount);
            if (ret != PAL_SUCCESS)
            {
                break;
            }

            //Check if end of file reached
            if (bytesCount == 0)
            {
                break;
            }

            ret = pal_fsFwrite(&dst_fd, buffer, bytesCount, &bytesCount);
            if (ret != PAL_SUCCESS)
            {
                break;
            }
        }
    }

    if (src_fd != 0)
    {
        pal_fsFclose(&src_fd);
    }
    if (dst_fd != 0)
    {
        pal_fsFclose(&dst_fd);
    }

    free(buffer);

    return ret;
}


PAL_PRIVATE bool pal_plat_findNextFile(DIR *dh, struct dirent ** CurrentEntry)
{
    bool ret = true;
    bool skip = false;
    bool foundFile = false;

    do
    {
        errno = 0;
        *CurrentEntry = vfs_readdir(dh);
        if (*CurrentEntry)
        {
            /* Skip the names "." and ".." as we don't want to remove them. also make sure that the current entry point to REGULER file*/
            skip = ((!strcmp((*CurrentEntry)->d_name, ".")) || (!strcmp((*CurrentEntry)->d_name, "..")));
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
        {
            ret = false;
            break; //Break from while
        }
    } while ((!foundFile) && (ret)); //While file has been found or ret is set to false

    return ret;
}


// Uh, the code has these high-level stuffs in pal_plat_fileSystem side, instead of having the loop
// in pal_fileSystem and the directory functions here?! In practice every plat will implement
// the dir iteration functions and copy-paste the higher level loops.
palStatus_t pal_plat_fsRmFiles(const char *pathName)
{
    DIR *dh = NULL; //Directory handler
    palStatus_t ret = PAL_SUCCESS;
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0}; //Buffer for coping the name and folder
    struct dirent * currentEntry = NULL; //file Entry

    PLAT_FS_DEBUG("pal_plat_fsRmFiles(%s)\n", pathName);

    dh = vfs_opendir(pathName);
    if (dh)
    {
        while (true)
        {
            if (!pal_plat_findNextFile(dh, &currentEntry))
            {
                break;
            }

            if (currentEntry)
            {
                PLAT_FS_DEBUG("path: %s, ce: %s, type: %d\n", pathName, currentEntry->d_name, currentEntry->d_type);
                pal_plat_addFileNameToPath(pathName, currentEntry->d_name, buffer);
                if (currentEntry->d_type == DT_DIR)
                {

                    ret = pal_plat_fsRmFiles(buffer);
                    if (ret != PAL_SUCCESS)
                    {
                        break;
                    }

                    // delete directory as it should now be empty (
                    ret = pal_plat_fsRmdir(buffer);
                    if (ret != PAL_SUCCESS)
                    {
                        break;
                    }
                }
                else
                {
                    ret = pal_plat_fsUnlink(buffer);
                    if (ret != PAL_SUCCESS)
                    {
                        break;
                    }
                }
            }
            else
            {//End of directory reached  without errors break, close directory and exit
                break;
            }
        }//while()
    }
    else//if (dh)
    {
        ret = PAL_ERR_FS_NO_PATH;
    }

    if (dh)
    {
        vfs_closedir(dh); //Close DIR handler
    }
    return ret;
}


palStatus_t pal_plat_fsCpFolder(const char *pathNameSrc,  char *pathNameDest)
{
    DIR *src_dh = NULL; //Directory for the source Directory handler
    palStatus_t ret = PAL_SUCCESS;
    struct dirent * currentEntry = NULL; //file Entry

    src_dh = vfs_opendir(pathNameSrc);
    if (src_dh == NULL)
    {
        ret = PAL_ERR_FS_NO_PATH;
    }

    if (ret == PAL_SUCCESS)
    {
        while(true)
        {
            currentEntry = NULL;
            if (!pal_plat_findNextFile(src_dh, &currentEntry))
            {
                break;
            }

            if (currentEntry)
            {
                if (currentEntry->d_type == DT_DIR)
                {
                    continue;
                }
                //copy the file to the destination
                ret = pal_plat_fsCpFile(pathNameSrc, pathNameDest, currentEntry->d_name);
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
    }

    if (src_dh)
    {
        vfs_closedir(src_dh);
    }
    return ret;
}


const char* pal_plat_fsGetDefaultRootFolder(pal_fsStorageID_t dataID)
{
    const char* returnedRoot = NULL;
    if (PAL_FS_PARTITION_PRIMARY == dataID)
    {
        returnedRoot = PAL_FS_MOUNT_POINT_PRIMARY;
    }
    else if (PAL_FS_PARTITION_SECONDARY == dataID)
    {
        returnedRoot = PAL_FS_MOUNT_POINT_SECONDARY;
    }
    else
    {
        // This should never happen, but let's be deterministic as the
        // enum has PAL_FS_PARTITION_LAST too.
        returnedRoot = "";
    }
    return returnedRoot;
}


// XXX: what is the purpose of this function? Is it supposed to decode utf8 filenames into unicode or something?
size_t pal_plat_fsSizeCheck(const char *stringToChk)
{
    return strlen(stringToChk);
}


palStatus_t pal_plat_fsFormat(pal_fsStorageID_t dataID)
{
    (void)dataID;

    // This is called if PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT is not set, but currently it's set for SXOS.
    return PAL_ERR_NOT_SUPPORTED;
}

#endif
