/*******************************************************************************
 * Copyright 2019 ARM Ltd.
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

#if PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM

/************************************************
    Module assumptions:
    * It will be used only in development stage
    * PAL_NUMBER_OF_PARTITIONS is 1
    * File open simultaneously can be up to 1
*************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "ns_list.h"

// PAL Includes
#include "pal.h"
#include "pal_plat_fileSystem.h"

#if (PAL_NUMBER_OF_PARTITIONS != 1)
    #error This File System Over RAM support only one partion
#endif

// Memory file item descriptor
typedef struct palMemFileDesc_ {

    bool                    is_file;    // is file or directory descriptor
    char*                   abs_name;   // absolute file name
    pal_fsFileMode_t        mode;       // file open mode
    uint8_t*                data_start; // data buffer start
    uint8_t*                data_pos;   // file current position, also indicate file is open
    size_t                  used_size;  // actual file data size
    size_t                  alloc_size; // actual buffer allocation size
    ns_list_link_t          link;       // link in g_mem_fd_list list

} palMemFileDesc_s;

// Memory file descriptors list
PAL_PRIVATE NS_LIST_HEAD(palMemFileDesc_s, link) g_mem_fd_list = NS_LIST_INIT(g_mem_fd_list);

#define TRACE_GROUP "PAL"

#define PAL_FS_INVALID_FILE_DESC ((palFileDescriptor_t)0)

#define PAL_MEM_FS_ALLOC_SIZE   256

PAL_PRIVATE palStatus_t pal_plat_fsCreateFD(const char *pathName, bool is_file, palMemFileDesc_s** fd_ctx_out)
{
    if (ns_list_count(&g_mem_fd_list) == 0) {
        printf("Warning, you are using FileSystem simulation over RAM.\n");
    }

    /* Allcate new FD */
    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)malloc(sizeof(palMemFileDesc_s));
    if (fd_ctx == NULL) {
        return PAL_ERR_NO_MEMORY;
    }

    memset(fd_ctx, 0, sizeof(palMemFileDesc_s));

    fd_ctx->is_file = is_file;

    /* Copy pathName to fd_ctx->abs_name */    
    fd_ctx->abs_name = (char*)malloc(strlen(pathName) + 1);
    if (fd_ctx->abs_name == NULL) {
        return PAL_ERR_NO_MEMORY;
    }
    strcpy(fd_ctx->abs_name, pathName);

    /* Allocate FD data buffer only for files */
    if (fd_ctx->is_file) {
        fd_ctx->used_size = 0;
        fd_ctx->alloc_size = PAL_MEM_FS_ALLOC_SIZE;
        fd_ctx->data_start = (uint8_t*)malloc(fd_ctx->alloc_size);
        if (fd_ctx->data_start == NULL) {
            return PAL_ERR_NO_MEMORY;
        }
        fd_ctx->data_pos = fd_ctx->data_start;
    }

    /* Add FD to list */
    ns_list_add_to_end(&g_mem_fd_list, fd_ctx);

    /* Set out param */
    *fd_ctx_out = fd_ctx;

    return PAL_SUCCESS;
}

PAL_PRIVATE void pal_plat_fsReleaseFD(palMemFileDesc_s* fd_ctx)
{
    /* Remove FD from list */
    ns_list_remove(&g_mem_fd_list, fd_ctx);

    /* Free FD's resources */
    if (fd_ctx->abs_name) {
        free(fd_ctx->abs_name);
    }
    if (fd_ctx->data_start) {
        free(fd_ctx->data_start);
    }
    /* Free FD */
    free(fd_ctx);
}

palStatus_t pal_plat_fsMkdir(const char *pathName)
{
    palMemFileDesc_s* fd_ctx = NULL;

    if (pathName == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* Check pathName is absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathName, PAL_FS_MOUNT_POINT_PRIMARY) != pathName) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* Check directory not exists by checking there is no files in that dir */
    ns_list_foreach(palMemFileDesc_s, tmp_fd_ctx, &g_mem_fd_list) {
        if (strstr(tmp_fd_ctx->abs_name, pathName) == tmp_fd_ctx->abs_name) {
            return PAL_ERR_FS_NAME_ALREADY_EXIST;
        }
    }

    return pal_plat_fsCreateFD(pathName, false, &fd_ctx);
}

palStatus_t pal_plat_fsRmdir(const char *pathName)
{
    palMemFileDesc_s* fd_ctx = NULL;

    if (pathName == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* Check pathName is absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathName, PAL_FS_MOUNT_POINT_PRIMARY) != pathName) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* Check directory is empty */
    ns_list_foreach(palMemFileDesc_s, tmp_fd_ctx, &g_mem_fd_list) {
        if (strcmp(tmp_fd_ctx->abs_name, pathName) == 0) {
            // The directory's FD
            fd_ctx = tmp_fd_ctx;
            continue;
        }
        if (strstr(tmp_fd_ctx->abs_name, pathName) == tmp_fd_ctx->abs_name) {
            return PAL_ERR_FS_DIR_NOT_EMPTY;
        }
    }

    if (fd_ctx == NULL) {
        // Directory not exists
        return PAL_ERR_FS_NO_PATH;
    }

    pal_plat_fsReleaseFD(fd_ctx);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFopen(const char *pathName, pal_fsFileMode_t mode, palFileDescriptor_t *fd)
{
    palStatus_t pal_status = PAL_SUCCESS;
    palMemFileDesc_s* fd_ctx = NULL;

    *fd = PAL_FS_INVALID_FILE_DESC;

    if (pathName == NULL || fd == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* Check pathName is absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathName, PAL_FS_MOUNT_POINT_PRIMARY) != pathName) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check if file exists */
    ns_list_foreach(palMemFileDesc_s, tmp_fd_ctx, &g_mem_fd_list) {
        if (strcmp(pathName, tmp_fd_ctx->abs_name) == 0) {
            // check this FD is not dir
            if (tmp_fd_ctx->is_file == false) {
                return PAL_ERR_FS_FILE_IS_DIR;
            }
            fd_ctx = tmp_fd_ctx;
            break;
        }
    }
    
    /* Proccess by mode */
    switch (mode)
    {
        case PAL_FS_FLAG_READONLY:
        case PAL_FS_FLAG_READWRITE:
            // File must exist.
            if (fd_ctx == NULL) {
                // file not exist
                return PAL_ERR_FS_NO_FILE;
            }
            if (fd_ctx->data_pos != NULL) {
                // file already open
                return PAL_ERR_FS_TOO_MANY_OPEN_FD;
            }
            // Sets data_pos to data_start
            fd_ctx->data_pos = fd_ctx->data_start;
            break;

        case PAL_FS_FLAG_READWRITEEXCLUSIVE:
            // If the file already exists, `fopen()` fails.
            if (fd_ctx != NULL) {
                // file already open
                return PAL_ERR_FS_NAME_ALREADY_EXIST;
            }
            // create new file
            pal_status = pal_plat_fsCreateFD(pathName, true, &fd_ctx);
            break;

        case PAL_FS_FLAG_READWRITETRUNC:
            // If the file already exists, it is truncated.
            if (fd_ctx != NULL) {
                if (fd_ctx->data_pos != NULL) {
                    // file already open
                    return PAL_ERR_FS_TOO_MANY_OPEN_FD;
                }
                // Reset data_pos to data_start and zero used_size
                fd_ctx->data_pos = fd_ctx->data_start;
                fd_ctx->used_size = 0;
            }
            else {
                // create new file
                pal_status = pal_plat_fsCreateFD(pathName, true, &fd_ctx);
            }
            break;

        default:
            return PAL_ERR_FS_INVALID_OPEN_FLAGS;
    }    

    /* If succeed, save mode and set out param */
    if (pal_status == PAL_SUCCESS) {
        fd_ctx->mode = mode;
        *fd = (palFileDescriptor_t)fd_ctx;
    }
    return pal_status;
}

palStatus_t pal_plat_fsFclose(palFileDescriptor_t *fd)
{
    if (fd == NULL || *fd == PAL_FS_INVALID_FILE_DESC) {
        // file already closed
        return PAL_SUCCESS;
    }

    // Set data_pos to NULL
    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)*fd;
    fd_ctx->data_pos = NULL;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFread(palFileDescriptor_t *fd, void * buffer, size_t numOfBytes, size_t *numberOfBytesRead)
{
    size_t available_size = 0;

    if (fd == NULL || *fd == PAL_FS_INVALID_FILE_DESC) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    if (buffer == NULL || numOfBytes == 0 || numberOfBytesRead == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Init out param */
    *numberOfBytesRead = 0;

    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)*fd;

    /* Check FD is valid and open */
    if (fd_ctx->data_pos == NULL || fd_ctx->data_start == NULL) {
        return PAL_ERR_FS_BAD_FD;
    }

    /* Calc available bytes for read */
    available_size = fd_ctx->used_size - (fd_ctx->data_pos - fd_ctx->data_start);
    if (numOfBytes > available_size) {
        numOfBytes = available_size;
    }
    /* Read file data to out buffer */
    if (numOfBytes > 0) {
        memcpy(buffer, fd_ctx->data_pos, numOfBytes);
        *numberOfBytesRead = numOfBytes;
        // Increase file current position
        fd_ctx->data_pos += numOfBytes;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFwrite(palFileDescriptor_t *fd, const void *buffer, size_t numOfBytes, size_t *numberOfBytesWritten)
{
    size_t required_size = 0;

    if (fd == NULL || *fd == PAL_FS_INVALID_FILE_DESC) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    if (buffer == NULL || numOfBytes == 0 || numberOfBytesWritten == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Init out param */
    *numberOfBytesWritten = 0;

    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)*fd;

    /* Check FD is valid and open */
    if (fd_ctx->data_pos == NULL || fd_ctx->data_start == NULL) {
        return PAL_ERR_FS_BAD_FD;
    }

    /* Check file open mode */
    if (fd_ctx->mode == PAL_FS_FLAG_READONLY) {
        return PAL_ERR_FS_ACCESS_DENIED;
    }

    /* Calc required buffer size after write */
    required_size = (fd_ctx->data_pos - fd_ctx->data_start) + numOfBytes;

    /* If current buffer size is in insufficient re-allocate bigger buffer */
    if (fd_ctx->alloc_size < required_size) {
        size_t pos_offset = (fd_ctx->data_pos - fd_ctx->data_start);
        // Calc new allocation size. Round-up to PAL_MEM_FS_ALLOC_SIZE
        size_t new_alloc_size = required_size;
        if ((new_alloc_size % PAL_MEM_FS_ALLOC_SIZE) > 0) {
            new_alloc_size += (PAL_MEM_FS_ALLOC_SIZE - (new_alloc_size % PAL_MEM_FS_ALLOC_SIZE));
        }
        fd_ctx->data_start = (uint8_t*)realloc(fd_ctx->data_start, new_alloc_size);
        if (fd_ctx->data_start == NULL) {
            return PAL_ERR_NO_MEMORY;
        }
        fd_ctx->alloc_size = new_alloc_size;
        // Update data_pos to new data buffer
        fd_ctx->data_pos = fd_ctx->data_start + pos_offset;
    }

    /* Write buffer to file data buffer */
    memcpy(fd_ctx->data_pos, buffer, numOfBytes);
    
    /* Increase file current position */
    fd_ctx->data_pos += numOfBytes;
    
    /* Increase used_size if write was not overwrite existing data */
    if (fd_ctx->used_size < (fd_ctx->data_pos - fd_ctx->data_start)) {
        fd_ctx->used_size = (fd_ctx->data_pos - fd_ctx->data_start);
    }

    /* Set out param */
    *numberOfBytesWritten = numOfBytes;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFseek(palFileDescriptor_t *fd, off_t offset, pal_fsOffset_t whence)
{    
    if (fd == NULL || *fd == PAL_FS_INVALID_FILE_DESC) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)*fd;

    /* Check FD is valid and open */
    if (fd_ctx->data_pos == NULL || fd_ctx->data_start == NULL) {
        return PAL_ERR_FS_BAD_FD;
    }

    uint8_t* new_data_pos = NULL;

    /* Move data_pos */
    switch (whence)
    {
        case PAL_FS_OFFSET_SEEKSET:
            new_data_pos = fd_ctx->data_start + offset;
            break;
        case PAL_FS_OFFSET_SEEKCUR:
            new_data_pos = fd_ctx->data_pos + offset;
            break;
        case PAL_FS_OFFSET_SEEKEND:
            new_data_pos = fd_ctx->data_start + fd_ctx->used_size + offset;
            break;
        default:
            return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check if new_data_pos exceed data buffer boundaries */
    if (new_data_pos < fd_ctx->data_start || new_data_pos > (fd_ctx->data_start + fd_ctx->used_size)) {
        return PAL_ERR_FS_OFFSET_ERROR;
    }

    /* Update fd_ctx->data_pos to new_data_pos */
    fd_ctx->data_pos = new_data_pos;
    
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFtell(palFileDescriptor_t *fd, off_t * pos)
{
    /* Init out param */
    *pos = -1;

    if (fd == NULL || *fd == PAL_FS_INVALID_FILE_DESC || pos == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    palMemFileDesc_s* fd_ctx = (palMemFileDesc_s*)*fd;
    if (fd_ctx->data_pos == NULL || fd_ctx->data_start == NULL) {
        return PAL_ERR_FS_BAD_FD;
    }

    /* Set out param to the offset in bytes of data_pos from data_start */
    *pos = (int32_t)(fd_ctx->data_pos - fd_ctx->data_start);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsUnlink(const char *pathName)
{
    if (pathName == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check pathName is absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathName, PAL_FS_MOUNT_POINT_PRIMARY) != pathName) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    ns_list_foreach_safe(palMemFileDesc_s, fd_ctx, &g_mem_fd_list) {
        if (strcmp(pathName, fd_ctx->abs_name) == 0) {
            // check this FD is not dir
            if (fd_ctx->is_file == false) {
                return PAL_ERR_FS_FILE_IS_DIR;
            }
            pal_plat_fsReleaseFD(fd_ctx);
            return PAL_SUCCESS;
        }
    }

    return PAL_ERR_FS_NO_FILE;
}

palStatus_t pal_plat_fsRmFiles(const char *pathName)
{
    bool path_exist = false;

    if (pathName == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check pathName is absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathName, PAL_FS_MOUNT_POINT_PRIMARY) != pathName) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Remove and free all FDs starting with pathName include sub-dirs, exclude the pathName dir itself */
    ns_list_foreach_safe(palMemFileDesc_s, fd_ctx, &g_mem_fd_list) {
        if (strcmp(fd_ctx->abs_name, pathName) == 0) {
            path_exist = true;
            continue;
        }
        if (strstr(fd_ctx->abs_name, pathName) == fd_ctx->abs_name) {
            pal_plat_fsReleaseFD(fd_ctx);
        }
    }

    if (path_exist == false) {
        return PAL_ERR_FS_NO_PATH;
    }
    return PAL_SUCCESS;
}

PAL_PRIVATE palStatus_t pal_plat_fsCpFile(palMemFileDesc_s* fd_ctx, const char *fileName, char *pathNameDest)
{
    palStatus_t pal_status = PAL_SUCCESS;
    palFileDescriptor_t new_fd = PAL_FS_INVALID_FILE_DESC;
    size_t bytes_written = 0;
    char dest_abs_name[PAL_MAX_FILE_AND_FOLDER_LENGTH];

    if ((strlen(pathNameDest) + strlen(fileName)) >= PAL_MAX_FILE_AND_FOLDER_LENGTH) {
        return PAL_ERR_FS_FILENAME_LENGTH;
    }

    /* build dest_abs_name. fileName is the file name start with '/' */
    strcpy(dest_abs_name, pathNameDest);
    strcat(dest_abs_name, fileName);

    /* Create new file and write source data to dest */
    pal_status = pal_plat_fsFopen(dest_abs_name, PAL_FS_FLAG_READWRITETRUNC, &new_fd);
    if (pal_status != PAL_SUCCESS) {
        return pal_status;
    }
    pal_status = pal_plat_fsFwrite(&new_fd, fd_ctx->data_start, fd_ctx->used_size, &bytes_written);
    if (pal_status != PAL_SUCCESS) {
        return pal_status;
    }
    if (bytes_written != fd_ctx->used_size) {
        return PAL_ERR_FS_ERROR;
    }
    pal_status = pal_plat_fsFclose(&new_fd);
    return pal_status;
}

palStatus_t pal_plat_fsCpFolder(const char *pathNameSrc, char *pathNameDest)
{
    palStatus_t pal_status = PAL_SUCCESS;
    bool src_exist = false;
    bool dest_exist = false;

    if (pathNameSrc == NULL || pathNameDest == NULL) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check pathNameSrc and pathNameDest are absolute, starts with PAL_FS_MOUNT_POINT_PRIMARY */
    if (strstr(pathNameSrc, PAL_FS_MOUNT_POINT_PRIMARY) != pathNameSrc ||
        strstr(pathNameDest, PAL_FS_MOUNT_POINT_PRIMARY) != pathNameDest) {
        return PAL_ERR_FS_INVALID_ARGUMENT;
    }

    /* Check src and dest dirs exists */
    ns_list_foreach(palMemFileDesc_s, fd_ctx, &g_mem_fd_list) {
        if (strcmp(fd_ctx->abs_name, pathNameSrc) == 0 && fd_ctx->is_file == false) {
            src_exist = true;
        }
        if (strcmp(fd_ctx->abs_name, pathNameDest) == 0 && fd_ctx->is_file == false) {
            dest_exist = true;
        }
        if (src_exist == true && dest_exist == true) {
            break;
        }
    }
    if (src_exist == false || dest_exist == false) {
        return PAL_ERR_FS_NO_PATH;
    }

    /* Duplicate only files starting with pathNameSrc, 
        exclude subdirs, files in subdirs and the pathNameSrc dir itself */
    ns_list_foreach(palMemFileDesc_s, fd_ctx, &g_mem_fd_list) {
        if (strstr(fd_ctx->abs_name, pathNameSrc) == fd_ctx->abs_name &&
            strcmp(fd_ctx->abs_name, pathNameSrc) != 0 &&
            fd_ctx->is_file == true) {
            size_t parent_dir_name_len = (strrchr(fd_ctx->abs_name, '/') - fd_ctx->abs_name);
            if (strncmp(fd_ctx->abs_name, pathNameSrc, parent_dir_name_len) != 0) {
                // Skip sub-dirs files
                continue;
            }
            // Copy file. Skip pathNameSrc and pass only file name with '/' as prefix
            pal_status = pal_plat_fsCpFile(fd_ctx, fd_ctx->abs_name + parent_dir_name_len, pathNameDest);
            if (pal_status != PAL_SUCCESS) {
                return pal_status;
            }
        }
    }

    return PAL_SUCCESS;
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

    return returnedRoot;
}

size_t pal_plat_fsSizeCheck(const char *stringToChk)
{
    return strlen(stringToChk);
}

palStatus_t pal_plat_fsFormat(pal_fsStorageID_t dataID)
{
    return pal_plat_fsRmFiles(pal_plat_fsGetDefaultRootFolder(dataID));
}

#endif