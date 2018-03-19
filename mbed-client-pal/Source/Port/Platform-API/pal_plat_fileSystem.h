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
#ifndef PAL_PALT_FILE_SYSTEM_H
#define PAL_PALT_FILE_SYSTEM_H

#include "pal_fileSystem.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_plat_fileSystem.h
*  \brief PAL file system - platform.
*	This file contains the file system APIs that need to be implemented in the platform layer.
*/

/*!  @defgroup PAL_PLAT_GROUP_FS
*	\note You need to add the prefix of the ESFS folder root stored in \c g_esfsRootFolder to all files and folders.
*	To change this, call \c pal_plat_fsSetEsfsRootFolder().
*
*/

/**
@defgroup PAL_PLAT_PUBLIC_FUNCTION  PAL Platform Public Functions
@ingroup PAL_PLAT_GROUP_FS
*/

/**
@addtogroup PAL_PLAT_PUBLIC_FUNCTION
@{*/

/*! \brief 	This function attempts to create a directory named \c pathName.
*
* @param[in]	*pathName A pointer to the null-terminated string that specifies the directory name to create.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note To remove a directory use \c PAL_ERR_FS_rmdir.
*
*\b Example
\code{.cpp}
	palStatus_t ret;
	ret = PAL_ERR_FS_mkdir("Dir1");
	if(!ret)
	{
		//Error
	}
\endcode
*/
palStatus_t pal_plat_fsMkdir(const char *pathName);



/*! \brief This function deletes a directory.
*
* @param[in]	*pathName A pointer to the null-terminated string that specifies the name of the directory to be deleted.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note The directory to be deleted \b must \b be \b Empty and \b closed.
*		The folder path must end with "/".
*		If given "..", the function changes the root directory to one directory down and deletes the working directory.
*/
palStatus_t pal_plat_fsRmdir(const char *pathName);



/*!\brief This function opens the file whose name is specified in the parameter `pathName` and associates it with a stream
*		   that can be identified in future operations by the `fd` pointer returned.
*
* @param[out]	fd A file descriptor for the file entered in the `pathName`.
* @param[in]	*pathName A pointer to the null-terminated string that specifies the file name to open or create.
* @param[in]	mode A mode flag that specifies the type of access and open method for the file.
*
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note	  The folder path must end with "/".
* \note	  If necessary, the platform layer \b allocates \b memory for the file descriptor. The structure
* 		  \c pal_plat_fclose() shall free that buffer.
* \note   The mode flags sent to this function are normalized to the \c pal_fsFileMode_t and each platform needs to replace them with the proper values.
*
*/
palStatus_t pal_plat_fsFopen(const char *pathName, pal_fsFileMode_t mode, palFileDescriptor_t *fd);



/*! \brief This function closes an open file object.
*
* @param[in] fd A pointer to the open file object structure to be closed.
*
* \return PAL_SUCCESS upon a successful operation. \n
*         PAL_FILE_SYSTEM_ERROR - see the error code \c palError_t.a 
*
* \note After successful execution of the function, the file object is no longer valid and it can be discarded.
* \note In some platforms, this function needs to \b free the file descriptor memory.
*/
palStatus_t pal_plat_fsFclose(palFileDescriptor_t *fd);



/*! \brief	This function reads an array of bytes from the stream and stores them in the block of memory
*			specified by the buffer. The position indicator of the stream is advanced by the total amount of bytes read.
*
* @param[in]	fd A pointer to the open file object structure.
* @param[in]	buffer A buffer for storing the read data.
* @param[in]	numOfBytes The number of bytes to read.
* @param[out]	numberOfBytesRead The number of bytes read.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note	After successful execution of the function,
*		`numberOfBytesRead` should be checked to detect end of the file.
*		If `numberOfBytesRead` is less than `numOfBytes`,
*		the read/write pointer has reached the end of the file during the read operation or an error has occurred.
*
*/
palStatus_t pal_plat_fsFread(palFileDescriptor_t *fd, void * buffer, size_t numOfBytes, size_t *numberOfBytesRead);



/*! \brief This function starts to write data from the \c buffer to the file at the position pointed by the read/write pointer.
*
* @param[in]	fd A pointer to the open file object structure.
* @param[in]	buffer A pointer to the data to be written.
* @param[in]	numOfBytes The number of bytes to write.
* @param[out]	numberOfBytesWritten The number of bytes written.
*
* \return PAL_SUCCESS upon a successful operation. \n
*           PAL_FILE_SYSTEM_ERROR - see the error code \c palError_t.
*
* \note The read/write pointer advances as number of bytes written. After successful execution of the function,
* \note `numberOfBytesWritten` should be checked to detect if the disk is full.
*		If `numberOfBytesWritten` is less than `numOfBytes`, the volume got full during the write operation.
*
*/
palStatus_t pal_plat_fsFwrite(palFileDescriptor_t *fd, const void *buffer, size_t numOfBytes, size_t *numberOfBytesWritten);


/*! \brief	This function moves the file read/write pointer without any read/write operation to the file.
*
* @param[in]	fd A pointer to the open file object structure.
* @param[in]	offset The byte offset from top of the file to set the read/write pointer.
* @param[out]   whence The offset is relative to this.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note - The `whence` options are:
* 		 -# \c PAL_ERR_FS_SEEKSET - relative to the start of the file.
*  		 -# \c PAL_ERR_FS_SEEKCUR - relative to the current position indicator.
* 		 -# \c PAL_ERR_FS_SEEKEND - relative to the end-of-file.
*
* \note In some systems, there is no \c whence argument.
* 	If you need to implement the `whence` argument:\n
* 	\b PAL_ERR_FS_SEEKEND - The function first finds the length of the file, then subtracts the file length from the position to find the relative path from the beginning.\n
*       \b PAL_ERR_FS_SEEKCUR - The function finds the current stream position and calculates the relative path from the file start.\n
*   
* In both options, \c fseek() needs to verify that the offset is smaller than the file end or start. 
*
*/
palStatus_t pal_plat_fsFseek(palFileDescriptor_t *fd, int32_t offset, pal_fsOffset_t whence);



/*! \brief This function gets the current read/write pointer of a file.
*
* @param[in]	fd A pointer to the open file object structure.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
*/
palStatus_t pal_plat_fsFtell(palFileDescriptor_t *fd, int32_t * pos);



/*! \brief This function deletes a \b single file from the file system.
*
* @param[in]  pathName A pointer to a null-terminated string that specifies the \b file to be removed.
* @param[in]  buildRelativeDirectory Needed to add a working directory to give \c pathName.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note The file \b must \b not \b be \b opened
*
*/
palStatus_t pal_plat_fsUnlink(const char *pathName);



/*! \brief This function deletes \b all files in a folder from the file system (FLAT remove only).
*
* @param[in]  pathName A pointer to a null-terminated string that specifies the \b folder.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note The folder \b must \b not \b be \b open and the folder path must end with "/".
* \note The process deletes one file at a time by calling \c pal_plat_fsUnlink until all files are removed.
* \note The function does not remove the directory found in the path.
*/
palStatus_t pal_plat_fsRmFiles(const char *pathName);



/*! \brief This function copies \b all files from a source folder to a destination folder (FLAT copy only).
*
* @param[in]  pathNameSrc A pointer to a null-terminated string that specifies the source folder.
* @param[in]  pathNameDest A pointer to a null-terminated string that specifies the destination folder (MUST exist).
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
* \note Both folders \b must \b not \b be \b open. If a folder does not exist the function fails.
* \note The process copies one file at a time until all files are copied.
* \note The function does not copy a directory found in the path.
*/
palStatus_t pal_plat_fsCpFolder(const char *pathNameSrc,  char *pathNameDest);


/*! \brief This function gets the default value for  root directory (primary)
*
* @param[in]  dataID - id of the data to ge the root folder for.
*
* \return pointer to the default path.
*
*/
const char* pal_plat_fsGetDefaultRootFolder(pal_fsStorageID_t dataID);



/*! \brief This function finds the length of the string received.
*
*
* @param[in]  stringToChk A pointer to the string received with a null terminator.
*
* \return The size of the string.
*
*/
size_t pal_plat_fsSizeCheck(const char *stringToChk);



/*! \brief This function sets up the mount point.
*
*
* @param void
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
*/
palStatus_t pal_plat_fsMountSystem(void);
/**
@} */


/*! \brief This function formats the SD partition indicated by `partitionID` (mapping the ID to an actual partition is done in the porting layer).
*
*
* @param[in] partitionID The ID of the partition to be formatted.
*
* \return PAL_SUCCESS upon a successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see the error code description \c palError_t.
*
*/
palStatus_t pal_plat_fsFormat(pal_fsStorageID_t dataID);


#ifdef __cplusplus
}
#endif
#endif
