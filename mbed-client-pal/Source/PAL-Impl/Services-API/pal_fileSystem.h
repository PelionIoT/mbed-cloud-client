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
#ifndef PAL_FILE_SYSTEM_H
#define PAL_FILE_SYSTEM_H

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

/*! \file pal_fileSystem.h
 *  \brief PAL pal_fileSystem.
*   This file contains the file system APIs. This is part of the PAL service API.
*	It provides APIs to create/remove directories and open/read/write to files. 
 */

/*! \mainpage
 *
 *\section file_sec File System
 *
 *\subsection rev_hist Revision History
 *     19-Jan-2017    Created and First Draft\n
 *     25-Jan-2017    Updated Design according to DR meeting \n
 *    02-Jan-2017 Minor implementation Changes \n
 *
 *
 *
 * \subsection int_sec Introduction
* This file gives the user an abstraction layer for POSIX like file systems.
 *
 *
 * \subsection req_sec Requirements
 * The requirements for PAL Version 1.2 are to support the following POSIX like APIs:
 *
 *
 *
 *\b Folder \b Operations \n
 *    -# mkdir        <a href="linkURL"> http://man7.org/linux/man-pages/man2/mkdir.2.html</a> \n
 *    -# rmdir()        <a href="linkURL"> http://man7.org/linux/man-pages/man2/rmdir.2.html</a> \n
 *
 *
 *\b File \b Operations \n
 *    -# fopen()      <a href="linkURL"> http://man7.org/linux/man-pages/man3/fopen.3.html</a> \n
 *    -# fclose()     <a href="linkURL"> http://man7.org/linux/man-pages/man3/fclose.3.html</a> \n
 *    -# fread()      <a href="linkURL"> http://man7.org/linux/man-pages/man3/fwrite.3.html</a> \n
 *    -# fwrite()     <a href="linkURL"> http://man7.org/linux/man-pages/man3/fwrite.3.html</a> \n
 *    -# fseek()      <a href="linkURL"> http://man7.org/linux/man-pages/man3/fseek.3.html</a> \n
 *    -# ftell()      <a href="linkURL"> http://man7.org/linux/man-pages/man3/fseek.3.html</a> \n
 *    -# unlink()     <a href="linkURL"> http://man7.org/linux/man-pages/man2/unlink.2.html</a> \n
 *
 *
 *\b Special \b Operations\n

*	-# rmfiles()	Delete folder content (files only) (flat deletion).
*	-# cpfiles()	Copy all files in folder to a different folder (flat copy).
 *
 *
 * \subsection Prerequisites
* 	User need to set up the file system on your project and mount the proper drive if needed. \n
 *
 *
 * \subsection Limitations
*	-# File size: Up to 2 GiB.\n
*	-# Filename length: PAL_MAX_FILE_NAME_SIZE.\n
*	-# Legal characters for object name: (file/directory name) are, (0-9), (a-z), (A - Z) (_ . # ). \n
*	-# System is case-insensitive. \n
*	-# The root folder can manage a maximum of 512 entries
*	-# Max path length is 66 Characters.
*	-# Folder shall be separated with "/"
*	-# All folder Paths shall end with "/"

 *
 *
 * \subsection  References
 *      PAL_FileSystemSpecification.doc
 */

/*!  @defgroup PAL_GROUP_FS
 *
 *
 */
/**
 @defgroup PAL_DEFINES  PAL Services Defined Symbols & Macros
 @ingroup PAL_GROUP_FS
 */

/**
 @defgroup PAL_ENUM  PAL Services Enumerated Data Types
 @ingroup PAL_GROUP_FS
 */

/**
 @defgroup PAL_PUBLIC_FUNCTION  PAL Services Public Functions
 @ingroup PAL_GROUP_FS
 */

/**
 @addtogroup PAL_DEFINES
 @{*/


#define PAL_MAX_FILE_NAME_SIZE		8				//!< Max length for file name received by user.
#define PAL_MAX_FILE_NAME_SUFFIX	3				//!< Max length for file name suffix.
#define PAL_MAX_FOLDER_DEPTH_CHAR	66				//!< Max folder length in chars.
#define PAL_MAX_FILE_AND_FOLDER_LENGTH	(PAL_MAX_FILE_NAME_SIZE + PAL_MAX_FILE_NAME_SUFFIX + PAL_MAX_FOLDER_DEPTH_CHAR + 1) //plus 1 is for "."
#define PAL_MAX_FULL_FILE_NAME	(PAL_MAX_FILE_NAME_SUFFIX + PAL_MAX_FOLDER_DEPTH_CHAR + 1) //plus 1 is for ".")

typedef uintptr_t palFileDescriptor_t; //!< Pointer to a generic File Descriptor object

/**
 @} */
/**
 @addtogroup PAL_ENUM
 @{*/

/** \brief Enum for `fseek()` relative options. */
typedef enum {
	PAL_FS_OFFSET_KEEP_FIRST = 0,
	PAL_FS_OFFSET_SEEKSET,		//!< Relative to the start of the file.
	PAL_FS_OFFSET_SEEKCUR,		//!< The current position indicator.
	PAL_FS_OFFSET_SEEKEND,		//!< End-of-file.
	PAL_FS_OFFSET_KEEP_LAST,

} pal_fsOffset_t;

/** \brief Enum for fopen() permission options*/
typedef enum {
	PAL_FS_FLAG_KEEP_FIRST = 0,
	PAL_FS_FLAG_READONLY,			//!< Open file for reading. The stream is positioned at the beginning of the file (file must exist), same as "r".\n
	PAL_FS_FLAG_READWRITE,			//!< Open for reading and writing. The stream is positioned at the beginning of the file (file must exist), same as "r+ ".\n
	PAL_FS_FLAG_READWRITEEXCLUSIVE,	//!< Open for reading and writing exclusively. If the file already exists, `fopen()` fails. The stream is positioned at the beginning of the file. same as "w+x"\n
	PAL_FS_FLAG_READWRITETRUNC,		//!< Open for reading and writing exclusively. If the file already exists, truncate file. The stream is positioned at the beginning of the file. same as "w+"\n
  PAL_FS_FLAG_KEEP_LAST,
} pal_fsFileMode_t;
/**
 @} */


/** \brief Enum for partition access. */
typedef enum {
    PAL_FS_PARTITION_PRIMARY = 0,        //!< Primary partition.\n
    PAL_FS_PARTITION_SECONDARY,  		 //!< Secondary partition.\n
    PAL_FS_PARTITION_LAST				 //!< Must be last value.\n
} pal_fsStorageID_t;


/**
 @addtogroup PAL_PUBLIC_FUNCTION
 @{*/

/*! \brief     This function attempts to create a directory named \c pathName.
 *

* @param[in]	*pathName A pointer to the null-terminated string that specifies the directory name to create.

 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note To remove a directory, use \c PAL_ERR_FS_rmdir.
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
palStatus_t pal_fsMkDir(const char *pathName);

/*! \brief This function deletes a directory
 *

* @param[in]	*pathName A pointer to the null-terminated string that specifies the directory name to be deleted.

 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *

* \note The deleted directory \b must \b be \b empty and \b closed and the
*		folder path shall end with "/".

 *
 *\b Example
 \code{.cpp}
 palStatus_t ret;
 ret = PAL_ERR_FS_mkdir("Dir1"); //Create folder name "Dir1"
 if(!ret)
 {
 //Error
 }
 ret = PAL_ERR_FS_rmdir("Dir1); //Remove directory from partition
 if(!ret)
 {
 //Error
 }
 \endcode
 */
palStatus_t pal_fsRmDir(const char *pathName);


/*!\brief This function opens the file whose name is specified in the parameter `pathName` and associates it with a stream
*		   that can be identified in future operations by the `fd` pointer returned.
 *
* @param[out]	fd The file descriptor to the file entered in the `pathName`.
* @param[in]	*pathName A pointer to the null-terminated string that specifies the file name to open or create.
* @param[in]	mode A mode flag that specifies the type of access and open method for the file.

 *
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *

* \note	  The folder path shall end with "/".

 *
 *\b Example
 \code{.cpp}
 //Copy File from "File1" to "File2"
 palStatus_t ret;
 palFileDescriptor_t fd1 = NULL,fd2 = NULL ; // File Object 1 & 2
 uint8 buffer[1024];
 size_t bytes_read = 0, Bytes_wrote = 0;

 //Open first file with Read permission
 ret = PAL_ERR_FS_fopen(&fd1, "File1", PAL_ERR_FS_READWRITEEXCLUSIVE);
 if(ret)    {//Error}

 //Create second file with Read/Write permissions
 ret = PAL_ERR_FS_fopen(&fd2, "File2", PAL_ERR_FS_READWRITEEXCLUSIVE);
 if(ret)    {//Error}

 //    Copy source to destination
 for (;;)
 {
 ret = PAL_ERR_FS_read(&fd1, buffer, sizeof(buffer), &bytes_read);    // Read a chunk of source file
 if (ret || bytes_read == 0) break;    // error or EOF
 ret = PAL_ERR_FS_write(&fd2, buffer, sizeof(buffer), &Bytes_wrote);    // Write it to the destination file
 if (ret || Bytes_wrote < bytes_read) break;    // error or disk full
 }

 PAL_ERR_FS_close(&fd1);
 PAL_ERR_FS_close(&fd2);
 }
 \endcode
 */
palStatus_t pal_fsFopen(const char *pathName, pal_fsFileMode_t mode,
        palFileDescriptor_t *fd);

/*! \brief This function closes an open file object.
 *
* @param[in] fd A pointer to the open file object structure to be closed.
 *
 *
* \return PAL_SUCCESS upon successful operation. \n
*         PAL_FILE_SYSTEM_ERROR - see error code \c palError_t.
 *
* \note When the function has completed successfully, the file object is no longer valid and it can be discarded.
 *
 */
palStatus_t pal_fsFclose(palFileDescriptor_t *fd);


/*! \brief This function reads an array of bytes from the stream and stores it in the block of memory
*			specified by buffer. The position indicator of the stream is advanced by the total amount of bytes read.
 *
* @param[in]	fd A pointer to the open file object structure.
* @param[in]	buffer The buffer to store the read data.
* @param[in]	numOfBytes The number of bytes to read.
* @param[out]	numberOfBytesRead The number of bytes read.

 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note	When the function has completed successfully,
*		`numberOfBytesRead` should be checked to detect end of the file.
*		If `numberOfBytesRead` is less than `numOfBytes`,
*		the read/write pointer has reached the end of the file during the read operation or there is an error.
 *
 */
palStatus_t pal_fsFread(palFileDescriptor_t *fd, void * buffer,
        size_t numOfBytes, size_t *numberOfBytesRead);

/*! \brief This function starts to write data from \c buffer to the file at the position pointed by the read/write pointer.
 *

* @param[in]	fd A pointer to the open file object structure.
* @param[in]	buffer A pointer to the data to be written.
* @param[in]	numOfBytes The number of bytes to write.
* @param[out]	numberOfBytesWritten The number of bytes written.
 *
* \return PAL_SUCCESS upon successful operation. \n
*           PAL_FILE_SYSTEM_ERROR - see error code \c palError_t.
 *
* \note The read/write pointer advances as number of bytes written. When the function has completed successfully,
* \note `numberOfBytesWritten` should be checked to detect the whether the disk is full.
*		If `numberOfBytesWritten` is less than `numOfBytes`, the volume got full during the write operation.

 *
 */
palStatus_t pal_fsFwrite(palFileDescriptor_t *fd, const void * buffer,
        size_t numOfBytes, size_t *numberOfBytesWritten);


/*! \brief This function moves the file read/write pointer without any read/write operation to the file.
 *
* @param[in]	fd A pointer to the open file object structure.
* @param[in]	offset The byte offset from the top of the file to set the read/write pointer.
* @param[out]   whence Where the offset is relative to.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note The `whence` options are: \n
* 		 -# PAL_ERR_FS_SEEKSET - Relative to the start of the file.
*  		 -# PAL_ERR_FS_SEEKCUR - The current position indicator.
* 		 -# PAL_ERR_FS_SEEKEND - End-of-file.
 *
 *\b Example
 \code{.cpp}
 palStatus_t ret;
 palFileDescriptor_t fd1 = NULL; // File Object 1
 uint8 buffer[1024];
 size_t bytes_read = 0, Bytes_wrote = 0;

 //Open file with Read permission
 ret = PAL_ERR_FS_fopen(&fd1, "File1", PAL_ERR_FS_READ);
 if(ret)    {//Error}

 ret = PAL_ERR_FS_fseek(&fd1, 500, PAL_ERR_FS_SEEKSET)

 \endcode
 */
palStatus_t pal_fsFseek(palFileDescriptor_t *fd, int32_t offset,
        pal_fsOffset_t whence);

/*! \brief This function gets the current read/write pointer of a file.
 *
* @param[in]	fd A pointer to the open file object structure.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
 */
palStatus_t pal_fsFtell(palFileDescriptor_t *fd, int32_t *pos);

/*! \brief This function deletes a \b single file from the file system.
 *
* @param[in]  pathName A pointer to a null-terminated string that specifies the \b file to be removed.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note The file \b must \b not \b be \b open.
 *
 */
palStatus_t pal_fsUnlink(const char *pathName);

/*! \brief This function deletes \b all files and folders in a folder from the file system (FLAT remove only).
 *
* @param[in]  pathName A pointer to a null-terminated string that specifies the folder.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note The folder \b must \b not \b be \b open and the folder path must end with "/".
 */
palStatus_t pal_fsRmFiles(const char *pathName);

/*! \brief This function copies \b all files from the source folder to the destination folder (FLAT copy only).
 *
* @param[in]  pathNameSrc A pointer to a null-terminated string that specifies the source folder.
* @param[in]  pathNameDest A pointer to a null-terminated string that specifies the destination folder (MUST exist).
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note Both folders \b must \b not \b be \b open. If the folders do not exist, the function fails.
 *
 *
 */
palStatus_t pal_fsCpFolder(const char *pathNameSrc, char *pathNameDest);

/*! \brief This function sets the mount directory for the given storage ID (primary or secondary), 
 *
* @param[in]  Path A pointer to a null-terminated string that specifies the root folder.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
*\note	If called with NULL, the ESFS root folder is set to default PAL_SOURCE_FOLDER.
*\note	The folder path must end with "/".
 */
palStatus_t pal_fsSetMountPoint(pal_fsStorageID_t dataID, const char *Path);

/*! \brief This function gets the mount directory for the given storage ID (primary or secondary), The function copies the path to the user pre allocated buffer.
 *
* @param[in]   length The length of the buffer.
* @param[out]  Path A pointer to \b pre-allocated \b buffer with \b size \c PAL_MAX_FOLDER_DEPTH_CHAR + 1 chars.
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t.
 *
* \note The plus 1 is for the '\0' terminator at the end of the buffer.
 */
palStatus_t pal_fsGetMountPoint(pal_fsStorageID_t dataID, size_t length, char *Path);


/*! \brief This function formats the SD partition indentified by the `partitionID` parameter.
 *
* @param[in] partitionID The ID of the partition to be formatted. (**Note:** The actual partition values mapped to the IDs is determined by the porting layer.)
 *
 * \return PAL_SUCCESS upon successful operation.\n
*         PAL_FILE_SYSTEM_ERROR - see error code description \c palError_t. \n
*         PAL_ERR_INVALID_ARGUMENT - an invalid `partitionID`.
 */
palStatus_t pal_fsFormat(pal_fsStorageID_t dataID);


/*! \brief This function will return if the partition used by pal only or not
 *
 * @param[in]   dataID - the ID of the data to be cleared (Note: the actual partition values mapped the IDs will be determined by the porting layer)
 *
 * \return true  - if partition is used only by pal.\n
 *         false - if partition is used by other component then pal.\n
 */
bool pal_fsIsPrivatePartition(pal_fsStorageID_t dataID);


/*! \brief This function will clean all file system resources 
 */
void pal_fsCleanup(void);


/**
 @} */

#endif//test
