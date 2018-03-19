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
#include "unity.h"
#include "unity_fixture.h"


#define TEST_DIR "dir1"
#define TEST_DIR2 "dir2"
#define TEST_WORKING_DIR "work1"
#define TEST_DIR_FILE "dir1/test.txt"
#define TEST_NUMBER_OF_FILE_TO_CREATE 20
#define TEST_BUFFER_SIZE 100
#define TEST_BUFFER_SMALL_SIZE 17
//#define TEST_BYTES_TO_WRITE 300*4
#define TEST_BYTES_TO_WRITE 100
#define TEST_FILE_NAME "%s/test_f%d"
#define BUFFER_TEST_SIZE 1123

#if (false == PAL_PRIMARY_PARTITION_PRIVATE)
    #define PAL_TEST_PRIMARY_PATH "/pri"
#else
    #define PAL_TEST_PRIMARY_PATH ""
#endif

#if (false == PAL_SECONDARY_PARTITION_PRIVATE)
    #define PAL_TEST_SECONDARY_PATH "/sec"
#else
    #define PAL_TEST_SECONDARY_PATH ""
#endif

//out should in length be PAL_MAX_FILE_AND_FOLDER_LENGTH
static char* addRootToPath(const char* in, char* out,pal_fsStorageID_t id)
{
    char root[PAL_MAX_FILE_AND_FOLDER_LENGTH] = { 0 };
    size_t len = 0;
    palStatus_t status;

    memset(out,0,PAL_MAX_FILE_AND_FOLDER_LENGTH);
    status = pal_fsGetMountPoint(id, PAL_MAX_FILE_AND_FOLDER_LENGTH, root);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    strncat(out, root, PAL_MAX_FILE_AND_FOLDER_LENGTH-1); //-1 for null terminator space
    len = strlen(out);
    if (PAL_FS_PARTITION_PRIMARY == id)
    {
        strncat(out, PAL_TEST_PRIMARY_PATH, PAL_MAX_FILE_AND_FOLDER_LENGTH - len);
    }
    else
    {
        strncat(out, PAL_TEST_SECONDARY_PATH, PAL_MAX_FILE_AND_FOLDER_LENGTH - len);
    }
    len = strlen(out);
    if (*in != '\0')
    {
        strncat(out,"/",PAL_MAX_FILE_AND_FOLDER_LENGTH - len);
        strncat(out,in,PAL_MAX_FILE_AND_FOLDER_LENGTH -len -1);
    }
    return(out);
}



PAL_PRIVATE uint8_t *bufferTest = NULL;
PAL_PRIVATE uint8_t *bufferTest2  = NULL;

PAL_PRIVATE palFileDescriptor_t g_fd1 = 0;
PAL_PRIVATE palFileDescriptor_t g_fd2 = 0;

PAL_PRIVATE palStatus_t pal_fsClearAndInitialyze(pal_fsStorageID_t id)
{
    palStatus_t status = PAL_SUCCESS;

    if (pal_fsIsPrivatePartition(id))
    {
        status = pal_fsFormat(id);
    }
    else
    {
        char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
        status = pal_fsRmFiles(addRootToPath("",buffer,id));
    }
    return(status);
}

/*! \brief This function compare two files
*
* @param[in]    *pathCmp1 - pointer to the null-terminated string that specifies the first filename to be compare
* @param[in]    *pathCmp2 - pointer to the null-terminated string that specifies the second filename to be compare
*
* \return PAL_SUCCESS upon successful operation.\n
*
*/
PAL_PRIVATE palStatus_t fileSystemCompareUtil(const char * pathCmp1, const char * pathCmp2)
{
    palStatus_t status = PAL_SUCCESS;

    char bufferCmp1[TEST_BUFFER_SIZE];
    char bufferCmp2[TEST_BUFFER_SIZE];
    size_t numOfBytesCmp1 = 0;
    size_t numOfBytesCmp2 = 0;
    palFileDescriptor_t  fdCmp1 = 0;
    palFileDescriptor_t  fdCmp2 = 0;

    status =  pal_fsFopen(pathCmp1, PAL_FS_FLAG_READONLY, &fdCmp1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    status =  pal_fsFopen(pathCmp2, PAL_FS_FLAG_READONLY, &fdCmp2);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    while(true)
    {

        status  = pal_fsFread(&fdCmp1, bufferCmp1, TEST_BUFFER_SIZE, &numOfBytesCmp1);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

        status  = pal_fsFread(&fdCmp2, bufferCmp2, TEST_BUFFER_SIZE, &numOfBytesCmp2);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

        if ((numOfBytesCmp2 == 0) && (numOfBytesCmp1 == 0))
        {//End of file reached
            break;
        }

        TEST_ASSERT_EQUAL(numOfBytesCmp1, numOfBytesCmp2);
        TEST_ASSERT_EQUAL_MEMORY(bufferCmp1, bufferCmp2, numOfBytesCmp1);
    }

    status =  pal_fsFclose(&fdCmp1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    status =  pal_fsFclose(&fdCmp2);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    return status;
}

TEST_GROUP(pal_fileSystem);

TEST_SETUP(pal_fileSystem)
{

    pal_init();
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};

    pal_fsRmFiles(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Delete Directory if exist
    pal_fsRmFiles(addRootToPath(TEST_WORKING_DIR,buffer,PAL_FS_PARTITION_PRIMARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_WORKING_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Delete Directory if exist
    pal_fsRmFiles(addRootToPath(TEST_DIR2,buffer,PAL_FS_PARTITION_PRIMARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_DIR2,buffer,PAL_FS_PARTITION_PRIMARY)); //Delete Directory if exist


    pal_fsRmFiles(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_SECONDARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_SECONDARY)); //Delete Directory if exist
    pal_fsRmFiles(addRootToPath(TEST_WORKING_DIR,buffer,PAL_FS_PARTITION_SECONDARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_WORKING_DIR,buffer,PAL_FS_PARTITION_SECONDARY)); //Delete Directory if exist
    pal_fsRmFiles(addRootToPath(TEST_DIR2,buffer,PAL_FS_PARTITION_SECONDARY));//Remove all files in the testing DIRECTORY
    pal_fsRmDir(addRootToPath(TEST_DIR2,buffer,PAL_FS_PARTITION_SECONDARY)); //Delete Directory if exist

    g_fd1 = 0;
    g_fd2 = 0;
    bufferTest = NULL;
    bufferTest2 = NULL;
    if(!pal_fsIsPrivatePartition(PAL_FS_PARTITION_PRIMARY))
    {

        addRootToPath("",buffer,PAL_FS_PARTITION_PRIMARY);
        pal_fsMkDir(buffer);
    }
    if(!pal_fsIsPrivatePartition(PAL_FS_PARTITION_SECONDARY))
    {
        addRootToPath("",buffer,PAL_FS_PARTITION_SECONDARY);
        pal_fsMkDir(buffer);
    }
}

TEST_TEAR_DOWN(pal_fileSystem)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    if (g_fd1) 
    {
        pal_fsFclose(&g_fd1);
    }
    if (g_fd2) 
    {
        pal_fsFclose(&g_fd2);
    }
    g_fd1 = 0;
    g_fd2 = 0;

    if (bufferTest != NULL)
    {
        free(bufferTest);
        bufferTest = NULL;
    }
    if (bufferTest2 != NULL)
    {
        free(bufferTest2);
        bufferTest2 = NULL;
    }
    pal_fsClearAndInitialyze(PAL_FS_PARTITION_PRIMARY);
    pal_fsClearAndInitialyze(PAL_FS_PARTITION_SECONDARY);

    if(!pal_fsIsPrivatePartition(PAL_FS_PARTITION_PRIMARY))
    {

        addRootToPath("",buffer,PAL_FS_PARTITION_PRIMARY);
        pal_fsRmDir(buffer);
    }
    if(!pal_fsIsPrivatePartition(PAL_FS_PARTITION_SECONDARY))
    {
        addRootToPath("",buffer,PAL_FS_PARTITION_SECONDARY);
        pal_fsRmDir(buffer);
    }
    pal_destroy();

}

/*! \brief /b SDFormat function tests formatting an SD card.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | create TEST_DIR with pal_fsMkDir                                                | PAL_SUCCESS |
* | 2 | create TEST_DIR_FILE file with pal_fsOpen                                       | PAL_SUCCESS |
* | 3 | close file TEST_DIR_FILE with pal_fsClose                                       | PAL_SUCCESS |
* | 4 | Format SD card with pal_FormatSDPartition                                       | PAL_SUCCESS |
* | 5 | TEST_DIR_FILE should not exist after format                                     | PAL_ERR_FS_NO_FILE |
* | 6 | create TEST_DIR with pal_fsMkDir                                                | PAL_SUCCESS |
*/
void SDFormat_1Partition()
{
    palStatus_t status = PAL_SUCCESS;
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};

    /*#1*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Create Directory
    if (PAL_SUCCESS == status)
    {
        /*#2*/
        status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_PRIMARY), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#3*/
        status = pal_fsFclose(&g_fd1);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }


    /*#4*/
    status = pal_fsClearAndInitialyze(PAL_FS_PARTITION_PRIMARY); //Format SD
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    /*#5*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_PRIMARY), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step
    
    status = pal_fsClearAndInitialyze(PAL_FS_PARTITION_SECONDARY); //Format SD
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);


    /*#6*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

}

/*! \brief /b SDFormat function tests formatting an SD card.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | create TEST_DIR with pal_fsMkDir primary partition                              | PAL_SUCCESS |
* | 2 | create TEST_DIR_FILE file with pal_fsOpen primary partition                     | PAL_SUCCESS |
* | 3 | close file TEST_DIR_FILE with pal_fsClose                                       | PAL_SUCCESS |
* | 4 | create TEST_DIR with pal_fsMkDir secondary partition                            | PAL_SUCCESS |
* | 5 | create TEST_DIR_FILE file with pal_fsOpen secondary partition                   | PAL_SUCCESS |
* | 6 | close file TEST_DIR_FILE with pal_fsClose                                       | PAL_SUCCESS |
* | 7 | Format SD card primary partition with pal_FormatSDPartition                     | PAL_SUCCESS |
* | 8 | TEST_DIR_FILE in primary should not exist after format                          | PAL_ERR_FS_NO_FILE |
* | 9 | TEST_DIR_FILE in secondary should  exist after format                           | PAL_SUCCESS |
* | 10| Format SD card secondary partition with pal_FormatSDPartition                   | PAL_SUCCESS |
* | 11| TEST_DIR_FILE in secondary should not exist after format                        | PAL_ERR_FS_NO_FILE |
* | 12| create TEST_DIR with pal_fsMkDir in primary partition                           | PAL_SUCCESS |
* | 13| create TEST_DIR with pal_fsMkDir in secondary partition                         | PAL_SUCCESS |
*/
void SDFormat_2Partition()
{
    palStatus_t status = PAL_SUCCESS;
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};

    /*#1*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Create Directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_PRIMARY), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_SECONDARY)); //Create Directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_SECONDARY), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);


    /*#7*/
    status = pal_fsClearAndInitialyze(PAL_FS_PARTITION_PRIMARY); //Format SD
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#8*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_PRIMARY), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

    /*#9*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_SECONDARY), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);    //the file still exists in secondary

    status = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#10*/
    status = pal_fsClearAndInitialyze(PAL_FS_PARTITION_SECONDARY); //Format SD
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#11*/
    status = pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,PAL_FS_PARTITION_SECONDARY), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

    /*#12*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_PRIMARY)); //Create Directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,PAL_FS_PARTITION_SECONDARY)); //Create Directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}



TEST(pal_fileSystem, SDFormat)
{
    SDFormat_2Partition();
    SDFormat_1Partition();
}


/*! \brief /b directoryTests function Tests  root Directory commands
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | get root directory with pal_fsGetMountPoint                                    | PAL_SUCCESS |
* | 2 | create TEST_WORKING_DIR with pal_fsMkDir                                       | PAL_SUCCESS |
* | 3 | Change Root Directory to TEST_WORKING_DIR with     pal_fsSetMountPoint         | PAL_SUCCESS |
* | 4 | create TEST_WORKING_DIR with pal_fsMkDir                                       | PAL_ERR_FS_NAME_ALREADY_EXIST |
* | 5 | get root directory with pal_fsGetMountPoint                                    | PAL_SUCCESS |
*/
void rootDirectoryTests(pal_fsStorageID_t storageId)
{
    palStatus_t status = PAL_SUCCESS;
    char getRootPath[TEST_BUFFER_SIZE] = { 0 };
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
/*#1*/
    status = pal_fsGetMountPoint(storageId, TEST_BUFFER_SIZE, getRootPath); //Setting New working Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    
/*#2*/
    status = pal_fsMkDir(addRootToPath(TEST_WORKING_DIR,buffer,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#3*/
    status = pal_fsSetMountPoint(storageId, addRootToPath(TEST_WORKING_DIR,buffer,storageId)); //Setting New working Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#4*/
    status = pal_fsMkDir(getRootPath); //should fail because already exits and path is absolute
    TEST_ASSERT_EQUAL(PAL_ERR_FS_NAME_ALREADY_EXIST, status);

/*#5*/
    status = pal_fsGetMountPoint(storageId, TEST_BUFFER_SIZE, getRootPath); //Setting New working Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

}


TEST(pal_fileSystem, rootDirectoryTests)
{

    rootDirectoryTests(PAL_FS_PARTITION_PRIMARY);

}


/*! \brief /b directoryTests function Tests Directory commands
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | create TEST_DIR with pal_fsMkDir                                                | PAL_SUCCESS |
* | 2 | create TEST_DIR with pal_fsMkDir                                                | PAL_ERR_FS_NAME_ALREADY_EXIST |
* | 3 | Create File TEST_DIR_FILE With PAL_ERR_FS_READWRITEEXCLUSIVE with pal_fsFopen   | PAL_SUCCESS |
* | 4 | Create File TEST_DIR_FILE With PAL_ERR_FS_READWRITEEXCLUSIVE with pal_fsFopen   | PAL_ERR_FS_NAME_ALREADY_EXIST |
* | 5 | Close file with uninitialized file descriptor                                   | PAL_ERR_FS_BAD_FD |
* | 6 | Close file with initialized file descriptor                                     | PAL_SUCCESS |
* | 7 | Delete directory with  pal_fsRmDir (directory not empty)                        | PAL_ERR_FS_ERROR |
* | 8 | Delete file TEST_DIR_FILE with pal_fsUnlink                                     | PAL_SUCCESS |
* | 9 | Delete file TEST_DIR_FILE with pal_fsUnlink                                     | PAL_SUCCESS |
* | 10 | Delete a folder which not exists with pal_fsUnlink                             | PAL_ERR_FS_NO_PATH |
*
*/
void directoryTests(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char *pathToFile = NULL;
    palStatus_t status = PAL_SUCCESS;

/*#1*/
    pathToFile = addRootToPath(TEST_DIR,buffer,storageId);
    status = pal_fsMkDir(pathToFile); //Create Directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

/*#2*/
    pathToFile = addRootToPath(TEST_DIR,buffer,storageId);
    status = pal_fsMkDir(pathToFile); //Create same Directory Shall failed
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_NAME_ALREADY_EXIST, status);

/*#3*/
    pathToFile = addRootToPath(TEST_DIR_FILE,buffer,storageId);
    status =  pal_fsFopen(pathToFile, PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

/*#4*/
    pathToFile = addRootToPath(TEST_DIR_FILE,buffer,storageId);
    status =  pal_fsFopen(pathToFile, PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd2); // Failed open Exclusively and file already created
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_NAME_ALREADY_EXIST, status);
/*#5*/
    #ifdef DEBUG
        pal_fsFclose(&g_fd2);//Failed fd1 was not a valid File descriptor
    #endif
    //TEST_ASSERT_EQUAL(PAL_ERR_FS_BAD_FD, status); //TODO Pass on mbedOS

/*#6*/    
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

/*#7*/
    pathToFile = addRootToPath(TEST_DIR,buffer,storageId);
    status = pal_fsRmDir(pathToFile); //Delete Directory Failed Directory not empty
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_DIR_NOT_EMPTY, status);

/*#8*/
    pathToFile = addRootToPath(TEST_DIR_FILE,buffer,storageId);
    status = pal_fsUnlink(pathToFile); //Delete the file in a directory
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

/*#9*/
    pathToFile = addRootToPath(TEST_DIR,buffer,storageId);
    status = pal_fsRmDir(pathToFile); //Delete Directory success
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

/*#10*/
    
    pathToFile = addRootToPath(TEST_DIR,buffer,storageId);
    status = pal_fsRmDir(pathToFile); //Delete not existing Directory
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_FS_NO_PATH, status);
}

TEST(pal_fileSystem, directoryTests)
{
    directoryTests(PAL_FS_PARTITION_PRIMARY);
    directoryTests(PAL_FS_PARTITION_SECONDARY);
}

/*! \brief /b FilesTests function Tests files commands
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Init Test                                                                                                       | |
* | 2 | create TEST_DIR with pal_fsMkDir                                                                                | PAL_SUCCESS |
* | 3 | create TEST_DIR2 with pal_fsMkDir                                                                               | PAL_SUCCESS |
* | 4 | Start Loop i from [0 - TEST_NUMBER_OF_FILE_TO_CREATE]                                                           | |
* | 5 | Create File in DIR_FILE named f_i (i - index of loop)with PAL_ERR_FS_READWRITEEXCLUSIVE mode using pal_fsFopen  | PAL_SUCCESS |
* | 6 | Write random buffer[TEST_BYTES_TO_WRITE] to file with pal_fsFwrite                                              | PAL_SUCCESS |
* | 7 | close file handler with pal_fsFclose                                                                            | PAL_SUCCESS |
* | 8 | End Loop                                                                                                        | |
* | 9 | Copy TEST_DIR folder to TEST_DIR2 with pal_fsCpFolder                                                           | PAL_SUCCESS |
* | 10 | Compare Folders                                                                                                | |
* | 11 | remove all files from TEST_DIR2                                                                                | PAL_SUCCESS |
* | 12 | remove all files from TEST_DIR                                                                                 | PAL_SUCCESS |
* | 13 | Start Loop i from [0 - TEST_NUMBER_OF_FILE_TO_CREATE]                                                          | |
* | 14 | open Files in DIR_FILE named f_i (i - index of loop) with PAL_ERR_FS_READONLY mode using pal_fsFopen           | PAL_ERR_FS_NO_FILE |
* | 15 | open Files in DIR_FILE named f_i (i - index of loop) with PAL_ERR_FS_READWRITE mode using pal_fsFopen          | PAL_ERR_FS_NO_FILE |
* | 16 | open Files in DIR_FILE2 named f_i (i - index of loop) with PAL_ERR_FS_READONLY mode using pal_fsFopen          | PAL_ERR_FS_NO_FILE |
* | 17 | open Files in DIR_FILE2 named f_i (i - index of loop) with PAL_ERR_FS_READWRITE mode using pal_fsFopen         | PAL_ERR_FS_NO_FILE |
* | 18 | remove TEST_DIR with pal_fsRmDir                                                                               | PAL_SUCCESS |
* | 19 | remove TEST_DIR2 with pal_fsRmDir                                                                              | PAL_SUCCESS |
* | 20 | try to remove a file that does not exist                                                                       | PAL_ERR_FS_NO_FILE |
* | 21 | try to remove a a variety of files that does not exist                                                         | PAL_ERR_FS_NO_PATH |
* | 22 | try to copy a non existing folder                                                                              | PAL_ERR_FS_NO_PATH |
*
*/
void FilesTests(pal_fsStorageID_t storageId)
{
    palStatus_t status = PAL_SUCCESS;
    char rootPathBuffer1[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char rootPathBuffer2[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char buffer1[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char buffer2[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    int i = 0;
    size_t numOfBytes;
/*#1*/
    //---------------- INIT TESTS----------------------------//
    memset(rootPathBuffer1, '1', PAL_MAX_FILE_AND_FOLDER_LENGTH);
    memset(rootPathBuffer2, '1', PAL_MAX_FILE_AND_FOLDER_LENGTH);
    //----------------END INIT TESTS-------------------------//

/*#2*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,rootPathBuffer1,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#3*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR2,rootPathBuffer2,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#4*/
    for(i = 0; i < TEST_NUMBER_OF_FILE_TO_CREATE; i++)
    {
/*#5*/
        snprintf(rootPathBuffer1, PAL_MAX_FILE_AND_FOLDER_LENGTH, TEST_FILE_NAME, TEST_DIR, i);
        status =  pal_fsFopen(addRootToPath(rootPathBuffer1,buffer1,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#6*/
        status =  pal_fsFwrite(&g_fd1, (void *)rootPathBuffer1, TEST_BYTES_TO_WRITE, &numOfBytes);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#7*/
        status =  pal_fsFclose(&g_fd1);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
/*#8*/
    }

/*#9*/
    status = pal_fsCpFolder(addRootToPath(TEST_DIR,rootPathBuffer1,storageId), addRootToPath(TEST_DIR2,rootPathBuffer2,storageId));//Copy all files from TEST_DIR to TEST_DIR2
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
/*#10*/
    for(i = 0; i < TEST_NUMBER_OF_FILE_TO_CREATE; i++)
    {
        snprintf(rootPathBuffer1, PAL_MAX_FILE_AND_FOLDER_LENGTH, TEST_FILE_NAME, TEST_DIR, i);
        snprintf(rootPathBuffer2, PAL_MAX_FILE_AND_FOLDER_LENGTH, TEST_FILE_NAME, TEST_DIR2, i);

        fileSystemCompareUtil(addRootToPath(rootPathBuffer1,buffer1,storageId), addRootToPath(rootPathBuffer2,buffer2,storageId));
    }

/*#11*/
    status = pal_fsRmFiles(addRootToPath(TEST_DIR2,rootPathBuffer2,storageId));//Remove all files in the testing DIRECTORY
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#12*/
    status = pal_fsRmFiles(addRootToPath(TEST_DIR,rootPathBuffer1,storageId));//Remove all files in the testing DIRECTORY
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#13*/
    for(i = 0; i < TEST_NUMBER_OF_FILE_TO_CREATE; i++)
    {
/*#14*/
        snprintf(buffer1, PAL_MAX_FILE_AND_FOLDER_LENGTH, TEST_FILE_NAME, TEST_DIR, i);
        status =  pal_fsFopen(addRootToPath(buffer1,rootPathBuffer1,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
        TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

/*#15*/
        status =  pal_fsFopen(addRootToPath(buffer1,rootPathBuffer1,storageId), PAL_FS_FLAG_READWRITE, &g_fd1);
        TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

/*#16*/
        snprintf(buffer2, PAL_MAX_FILE_AND_FOLDER_LENGTH, TEST_FILE_NAME, TEST_DIR2, i);
        status =  pal_fsFopen(addRootToPath(buffer2,rootPathBuffer2,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
        TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

/*#17*/
        status =  pal_fsFopen(addRootToPath(buffer1,rootPathBuffer1,storageId), PAL_FS_FLAG_READWRITE, &g_fd1);
        TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);    //Failed all files where deleted in previous step

    }

/*#18*/
    status = pal_fsRmDir(addRootToPath(TEST_DIR,buffer1,storageId));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#19*/
    status = pal_fsRmDir(addRootToPath(TEST_DIR2,buffer2,storageId));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#20*/
    status = pal_fsUnlink(addRootToPath("aaaa.t",rootPathBuffer1, storageId));//not existing file
    TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_FILE, status);

/*#21*/
    status = pal_fsRmFiles(addRootToPath("aaaaa",rootPathBuffer1, storageId));//Remove all file in not existing directory
    TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_PATH, status);

/*#22*/

    status = pal_fsCpFolder(addRootToPath("aaaaa", rootPathBuffer1, storageId), addRootToPath("bbbb" ,rootPathBuffer2,storageId)); //copy from not existing dir
    TEST_ASSERT_EQUAL(PAL_ERR_FS_NO_PATH, status);
}

TEST(pal_fileSystem, FilesTests)
{
    FilesTests(PAL_FS_PARTITION_PRIMARY);
    FilesTests(PAL_FS_PARTITION_SECONDARY);
}

/*! \brief /b FilesTestsSeek function Tests \b fseek() , \b fteel() & \b fread() function
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | create TEST_DIR with pal_fsMkDir                                                        | PAL_SUCCESS |
* | 2 | Create File TEST_DIR_FILE With PAL_ERR_FS_READWRITETRUNC with pal_fsFopen               | PAL_SUCCESS |
* | 3 | Create buffer[TEST_BUFFER_SIZE] with incremental data, Buffer size TEST_BUFFER_SIZE     | PAL_SUCCESS |
* | 4 | Write buffer to file with pal_fsFwrite                                                  | PAL_SUCCESS |
* | 5 | Start Loop     i from [0 - TEST_BUFFER_SIZE]                                            | |
* | 6 | run pal_fsFseek with PAL_FS_OFFSET_SEEKSET option and incremental offset i              | PAL_SUCCESS |
* | 7 | run    pal_fsFtell and compare offset to i                                              | PAL_SUCCESS |
* | 8 | run    pal_fsFread, read one byte and compare it to the buffer[i]                       | PAL_SUCCESS |
* | 9 | End Loop                                                                                | |
* | 10 | Start Loop i from [0 - TEST_BUFFER_SIZE]                                               | |
* | 11 | run pal_fsFseek with PAL_FS_OFFSET_SEEKEND option and incremental offset (-1)*i        | PAL_SUCCESS |
* | 12 | run pal_fsFtell and compare offset to TEST_BUFFER_SIZE - i                             | PAL_SUCCESS |
* | 13 | End Loop                                                                               | |
* | 14 | run pal_fsFseek with PAL_FS_OFFSET_SEEKSET option offset TEST_BUFFER_SIZE/2            | PAL_SUCCESS |
* | 15 | Start Loop i from [0 - TEST_BUFFER_SIZE/10]                                            | |
* | 16 | run pal_fsFseek with PAL_FS_OFFSET_SEEKEND option and incremental offset i             | PAL_SUCCESS |
* | 17 | run    pal_fsFtell and compare offset to i                                             | PAL_SUCCESS |
* | 18 | End Loop                                                                               | |
* | 19 | Cleanup                                                                                | PAL_SUCCESS |
*
*/
void FilesTestsSeek(pal_fsStorageID_t storageId)
{
    palStatus_t status = PAL_SUCCESS;
    char buffer[TEST_BUFFER_SIZE];
    int i = 0;
    size_t numOfBytes;
    int32_t pos = 0;
    char read_buf = 1;
    size_t prePos = 0;
/*#1*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#2*/
    status =  pal_fsFopen(addRootToPath(TEST_DIR_FILE,buffer,storageId), PAL_FS_FLAG_READWRITETRUNC, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#3*/
    for(i = 0; i < TEST_BUFFER_SIZE; i++)
    {
        buffer[i] = i;
    }

/*#4*/
    status =  pal_fsFwrite(&g_fd1, (void *)buffer, TEST_BUFFER_SIZE, &numOfBytes);  //Write incremental buffer for seek testing
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BUFFER_SIZE, numOfBytes);

/*#5*/
    //Test Seek "PAL_FS_OFFSET_SEEKSET"
    for(i = 0; i < TEST_BUFFER_SIZE; i++)
    {

/*#6*/    
        status = pal_fsFseek(&g_fd1, i, PAL_FS_OFFSET_SEEKSET); //Set position to start of the stream
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#7*/    
        status = pal_fsFtell(&g_fd1, &pos); //Check if position is in the start of the stream
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL(i, pos);

/*#8*/    
        status  = pal_fsFread(&g_fd1, &read_buf, 1, &numOfBytes);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL(1, numOfBytes);
        TEST_ASSERT_EQUAL(buffer[i], read_buf);

/*#9*/
    }
    
/*#10*/
    //Test Seek "PAL_FS_OFFSET_SEEKEND"
    for(i = 0; i < TEST_BUFFER_SIZE; i++)
    {
/*#11*/    
        status = pal_fsFseek(&g_fd1, (-1)*i, PAL_FS_OFFSET_SEEKEND); //Set position to end  of the stream
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#12*/    
        status = pal_fsFtell(&g_fd1, &pos); //Get position
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL(TEST_BUFFER_SIZE - i, pos);

/*#13*/
    }

/*#14*/
    //Test Seek "PAL_ERR_FS_SEEKCUR"
    status = pal_fsFseek(&g_fd1, TEST_BUFFER_SIZE/2, PAL_FS_OFFSET_SEEKSET); //Set position to middle of the stream
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    prePos = TEST_BUFFER_SIZE/2;

/*#15*/
    for(i = 0; i < TEST_BUFFER_SIZE/10 ; i++)
    {

/*#16*/    
        status = pal_fsFseek(&g_fd1, i, PAL_FS_OFFSET_SEEKCUR); //Set position to start of the stream
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*17*/    
        status = pal_fsFtell(&g_fd1, &pos); //Get position
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL(prePos + i, pos);
        prePos = pos;

/*#18*/
    }

/*#19*/
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
}


TEST(pal_fileSystem, FilesTestsSeek)
{
    FilesTestsSeek(PAL_FS_PARTITION_PRIMARY);
#if (PAL_NUMBER_OF_PARTITIONS == 2)
    FilesTestsSeek(PAL_FS_PARTITION_SECONDARY);
#endif
}

/*! \brief /b FilesPermission function Tests \b fopen() with r
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Init Test                                                                               | Success |
* | 2 | create TEST_DIR with pal_fsMkDir                                                        | PAL_SUCCESS |
* | 3 | create new file using fopen with PAL_FS_FLAG_READWRITEEXCLUSIVE                         | PAL_SUCCESS |
* | 4 | write buffer to file                                                                    | PAL_SUCCESS |
* | 5 | close file                                                                              | PAL_SUCCESS |
* | 6 | open file using fopen() with PAL_FS_FLAG_READONLY                                       | PAL_SUCCESS |
* | 7 | write buffer to file with fwrite()                                                      | failed |
* | 8 | read buffer from file with fread()                                                      | PAL_SUCCESS |
* | 9 | close file                                                                              | PAL_SUCCESS |
* | 10 | remove all files in folder                                                             | PAL_SUCCESS |
* | 11 | remove folder                                                                          | PAL_SUCCESS |
*/
void FilesPermission_read_only(pal_fsStorageID_t storageId)
{
    palStatus_t status = PAL_SUCCESS;
    char readBuffer[TEST_BUFFER_SIZE];
    char readBuffer2[TEST_BUFFER_SIZE];
    char filename[TEST_BUFFER_SIZE];
    size_t numOfBytes = 0;
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};

/*#1*/
    //---------------- INIT TESTS----------------------------//
    memset(readBuffer, '1', TEST_BUFFER_SIZE);
    //----------------END INIT TESTS-------------------------//

/*#2*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    snprintf(filename, TEST_BUFFER_SIZE, TEST_FILE_NAME, TEST_DIR, 1);
/*#3*/
    status =  pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#4*/
    status =  pal_fsFwrite(&g_fd1, (void *)readBuffer, TEST_BYTES_TO_WRITE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BYTES_TO_WRITE, numOfBytes);

/*#5*/
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#6*/
    status =  pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#7*/
    pal_fsFwrite(&g_fd1, (void *)readBuffer, TEST_BYTES_TO_WRITE, &numOfBytes);
    TEST_ASSERT_EQUAL(0, numOfBytes);

/*#8*/
    status = pal_fsFread(&g_fd1, readBuffer2, TEST_BUFFER_SIZE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BUFFER_SIZE, numOfBytes);
    TEST_ASSERT_EQUAL_MEMORY(readBuffer, readBuffer2, TEST_BUFFER_SIZE);

/*#9*/
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#10*/
    status = pal_fsRmFiles(addRootToPath(TEST_DIR,buffer,storageId));//Remove all files in the testing DIRECTORY
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#11*/
    status = pal_fsRmDir(addRootToPath(TEST_DIR,buffer,storageId)); //Delete Directory if exist
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
}

TEST(pal_fileSystem, FilesPermission_read_only)
{
    FilesPermission_read_only(PAL_FS_PARTITION_PRIMARY);
    FilesPermission_read_only(PAL_FS_PARTITION_SECONDARY);
}


/*! \brief /b FilesPermission function Tests \b fopen() with r+
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Init Test                                                                               | Success |
* | 2 | create TEST_DIR with pal_fsMkDir                                                        | PAL_SUCCESS |
* | 3 | create new file using fopen with PAL_FS_FLAG_READWRITEEXCLUSIVE                         | PAL_SUCCESS |
* | 4 | write buffer to file                                                                    | PAL_SUCCESS |
* | 5 | close file                                                                              | PAL_SUCCESS |
* | 6 | open file using fopen() with PAL_FS_FLAG_READONLY                                       | PAL_SUCCESS |
* | 7 | write buffer to file with fwrite()                                                      | PAL_SUCCESS |
* | 8 | seek to the begining of the file                                                        | PAL_SUCCESS |
* | 9 | read buffer from file with fread()                                                      | PAL_SUCCESS |
* | 10 | close file                                                                             | PAL_SUCCESS |
* | 11 | remove all files in folder                                                             | PAL_SUCCESS |
* | 12 | remove folder                                                                          | PAL_SUCCESS |
*/
void FilesPermission_read_write(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palStatus_t status = PAL_SUCCESS;
    char readBuffer[TEST_BUFFER_SIZE];
    char readBuffer2[TEST_BUFFER_SIZE];
    char filename[TEST_BUFFER_SIZE];
    size_t numOfBytes = 0;

/*#1*/
    //---------------- INIT TESTS----------------------------//
    memset(readBuffer, '1', TEST_BUFFER_SIZE);
    //----------------END INIT TESTS-------------------------//

/*#2*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    snprintf(filename, TEST_BUFFER_SIZE, TEST_FILE_NAME, TEST_DIR, 1);
/*#3*/
    status =  pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#4*/
    status =  pal_fsFwrite(&g_fd1, (void *)readBuffer, TEST_BYTES_TO_WRITE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BYTES_TO_WRITE, numOfBytes);

/*#5*/
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#6*/
    status =  pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READWRITE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#7*/
    status =  pal_fsFwrite(&g_fd1, (void *)readBuffer, TEST_BYTES_TO_WRITE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BYTES_TO_WRITE, numOfBytes);

/*#8*/
    status = pal_fsFseek(&g_fd1, 0, PAL_FS_OFFSET_SEEKSET); //Set position to start of the stream
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#9*/
    status = pal_fsFread(&g_fd1, readBuffer2, TEST_BUFFER_SIZE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BYTES_TO_WRITE, numOfBytes);
    TEST_ASSERT_EQUAL_MEMORY(readBuffer, readBuffer2, TEST_BUFFER_SIZE);

/*#10*/
    status =  pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#11*/
    status = pal_fsRmFiles(addRootToPath(TEST_DIR,buffer,storageId));//Remove all files in the testing DIRECTORY
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#12*/
    status = pal_fsRmDir(addRootToPath(TEST_DIR,buffer,storageId)); //Delete Directory if exist
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
}


TEST(pal_fileSystem, FilesPermission_read_write)
{
    FilesPermission_read_write(PAL_FS_PARTITION_PRIMARY);
    FilesPermission_read_write(PAL_FS_PARTITION_SECONDARY);
}


/*! \brief /b FilesPermission function Tests \b fopen() with w+x
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Init Test                                                                               | Success |
* | 2 | create TEST_DIR with pal_fsMkDir                                                        | PAL_SUCCESS |
* | 3 | create new file using fopen with PAL_FS_FLAG_READWRITEEXCLUSIVE                         | PAL_SUCCESS |
* | 4 | write buffer to file                                                                    | PAL_SUCCESS |
* | 5 | close file                                                                              | PAL_SUCCESS |
* | 6 | open file using fopen() withPAL_FS_FLAG_READWRITETRUNC                                  | PAL_SUCCESS |
* | 7 | read buffer from file with fread()                                                      | PAL_SUCCESS with read length 0 |
* | 8 | close file                                                                              | PAL_SUCCESS |
* | 9 | remove all files in folder                                                              | PAL_SUCCESS |
* | 10 | remove folder                                                                          | PAL_SUCCESS |
*/
void FilesPermission_read_write_trunc(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palStatus_t status = PAL_SUCCESS;
    char readBuffer[TEST_BUFFER_SIZE];
    char filename[TEST_BUFFER_SIZE];
    size_t numOfBytes = 0;

/*#1*/
    //---------------- INIT TESTS----------------------------//
    memset(readBuffer, '1', TEST_BUFFER_SIZE);
    //----------------END INIT TESTS-------------------------//

/*#2*/
    status = pal_fsMkDir(addRootToPath(TEST_DIR,buffer,storageId)); //Create Directory
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

    snprintf(filename, TEST_BUFFER_SIZE, TEST_FILE_NAME, TEST_DIR, 1);
/*#3*/
    status = pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#4*/
    status = pal_fsFwrite(&g_fd1, (void *)readBuffer, TEST_BYTES_TO_WRITE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(TEST_BYTES_TO_WRITE, numOfBytes);

/*#5*/
    status = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#6*/
    status = pal_fsFopen(addRootToPath(filename,buffer,storageId), PAL_FS_FLAG_READWRITETRUNC, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#7*/
    status = pal_fsFread(&g_fd1, readBuffer, TEST_BUFFER_SIZE, &numOfBytes);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, numOfBytes); //nothing to read empty file

/*#8*/
    status = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#9*/
    status = pal_fsRmFiles(addRootToPath(TEST_DIR,buffer,storageId));//Remove all files in the testing DIRECTORY
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

/*#10*/
    status = pal_fsRmDir(addRootToPath(TEST_DIR,buffer,storageId)); //Delete Directory if exist
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
}


TEST(pal_fileSystem, FilesPermission_read_write_trunc)
{
    FilesPermission_read_write_trunc(PAL_FS_PARTITION_PRIMARY);
    FilesPermission_read_write_trunc(PAL_FS_PARTITION_SECONDARY);
}


void create_write_and_read_pal_file(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char fileName[] = "fileName";
    palStatus_t res = PAL_SUCCESS;
    size_t num_bytes_write = 0;
    size_t num_bytes_read = 0;

    uint32_t i = 0;

    bufferTest = malloc(BUFFER_TEST_SIZE);
    TEST_ASSERT_NOT_EQUAL(bufferTest, NULL);
    bufferTest2 = malloc(BUFFER_TEST_SIZE);
    TEST_ASSERT_NOT_EQUAL(bufferTest2, NULL);
    memset(bufferTest, 0, BUFFER_TEST_SIZE);
    memset(bufferTest2, 0, BUFFER_TEST_SIZE);

    for (i = 0; i < BUFFER_TEST_SIZE; i++){
            bufferTest[i] = (uint8_t)(i % 256);
    }

    pal_fsUnlink(addRootToPath(fileName,buffer,storageId));

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &(g_fd1));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFwrite(&(g_fd1), bufferTest, BUFFER_TEST_SIZE, &num_bytes_write);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(BUFFER_TEST_SIZE, num_bytes_write);

    res = pal_fsFclose(&(g_fd1));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READONLY, &(g_fd1));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFread(&(g_fd1), bufferTest2, 223, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(223, num_bytes_read);

    // split the reads
    res = pal_fsFread(&(g_fd1), bufferTest2, 900, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(900, num_bytes_read);


    // Compare the buffers � here we have a mismatch in location buffer2[288]
    TEST_ASSERT_EQUAL_INT8_ARRAY(&(bufferTest[223]), bufferTest2, 900);

    res = pal_fsFclose(&(g_fd1));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsUnlink(addRootToPath(fileName,buffer,storageId));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    free(bufferTest);
    bufferTest = NULL;
    free(bufferTest2);
    bufferTest2 = NULL;
    
}


TEST(pal_fileSystem, create_write_and_read_pal_file)
{
    create_write_and_read_pal_file(PAL_FS_PARTITION_PRIMARY);
    create_write_and_read_pal_file(PAL_FS_PARTITION_SECONDARY);
}

void WriteInTheMiddle(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char fileName[] = "fileName";
    const uint32_t inputSizeSmall = (TEST_BUFFER_SIZE * 6) + 1;
    const uint32_t inputSizeBig = BUFFER_TEST_SIZE;
    palStatus_t res = PAL_SUCCESS;
    size_t num_bytes_write = 0;
    size_t num_bytes_read = 0;
    unsigned char *smallBuffer = NULL;
    const size_t offset = 200;
    uint32_t residue = inputSizeBig - (offset + inputSizeSmall);

    bufferTest = malloc(inputSizeBig);
    TEST_ASSERT_NOT_EQUAL(bufferTest, NULL);
    bufferTest2 = malloc(inputSizeBig);
    TEST_ASSERT_NOT_EQUAL(bufferTest2, NULL);
    smallBuffer = malloc(inputSizeSmall);
    TEST_ASSERT_NOT_EQUAL(smallBuffer, NULL);
    memset(bufferTest, 0, inputSizeBig);
    memset(bufferTest2, 0, inputSizeBig);
    memset(smallBuffer, 0, inputSizeSmall);

    // create 1123 bytes buffer filled with the numbers 0..255
    for (uint32_t i = 0; i < inputSizeBig; i++)
    {
        bufferTest[i] = (uint8_t)(i % 256);
    }

    // create 601 bytes buffer filled with only 0xCC
    for (uint32_t i = 0; i < inputSizeSmall; i++)
    {
        smallBuffer[i] = 0xCC;
    }

    pal_fsUnlink(addRootToPath(fileName,buffer,storageId));
    TEST_ASSERT((PAL_SUCCESS == res) || (PAL_ERR_FS_NO_FILE == res));

    /* 1. Write bufferTest data to file, read it and compare read content to bufferTest */
    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFwrite(&g_fd1, bufferTest, inputSizeBig, &num_bytes_write);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(inputSizeBig, num_bytes_write);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFread(&g_fd1, bufferTest2, inputSizeBig, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(inputSizeBig, num_bytes_read);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(bufferTest, bufferTest2, inputSizeBig);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    /* 
    2. Write smallBuffer data to offset 201 of the file and then compare each fragment:
        - offset 0..200 equal to bufferTest[0..200]
        - offset 201..801 equal to smallBuffer
        - offset 802..1122 equal to bufferTest[802..1122]
    */
    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READWRITE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFseek(&g_fd1, offset, PAL_FS_OFFSET_SEEKSET);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFwrite(&g_fd1, smallBuffer, inputSizeSmall, &num_bytes_write);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(inputSizeSmall, num_bytes_write);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    // offset 0..200 equal to bufferTest[0..200]
    res = pal_fsFread(&g_fd1, bufferTest2, offset, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(offset, num_bytes_read);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(bufferTest, bufferTest2, offset);

    // offset 201..801 equal to smallBuffer
    res = pal_fsFread(&g_fd1, bufferTest2, inputSizeSmall, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(inputSizeSmall, num_bytes_read);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(smallBuffer, bufferTest2, inputSizeSmall);

    // offset 802..1122 equal to bufferTest[802..1122]
    res = pal_fsFread(&g_fd1, bufferTest2, residue, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(residue, num_bytes_read);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(bufferTest + offset + inputSizeSmall, bufferTest2, residue);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsUnlink(addRootToPath(fileName,buffer,storageId));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    free(bufferTest);
    bufferTest = NULL;
    free(bufferTest2);
    bufferTest2 = NULL;
    free(smallBuffer);
    smallBuffer = NULL;
}

TEST(pal_fileSystem, WriteInTheMiddle)
{
    WriteInTheMiddle(PAL_FS_PARTITION_PRIMARY);
    WriteInTheMiddle(PAL_FS_PARTITION_SECONDARY);
}




void SequentialWriteAndRead(pal_fsStorageID_t storageId)
{
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    char fileName[] = "fileName";
    palStatus_t res = PAL_SUCCESS;
    size_t num_bytes_write = 0;
    size_t num_bytes_read = 0;
    unsigned char small_write_buffer[TEST_BUFFER_SMALL_SIZE] = {
        0x2D, 0x6B, 0xAC, 0xCC, 0x08, 0x6B, 0x14, 0x82,
        0xF3, 0x0C, 0xF5, 0x67, 0x17, 0x23, 0x50, 0xB4,
        0xFF
    };
    unsigned char small_read_buffer[TEST_BUFFER_SMALL_SIZE] = { 0 };
    bufferTest = malloc(BUFFER_TEST_SIZE);
    TEST_ASSERT_NOT_EQUAL(bufferTest, NULL);
    bufferTest2 = malloc(BUFFER_TEST_SIZE);
    TEST_ASSERT_NOT_EQUAL(bufferTest2, NULL);
    memset(bufferTest, 0, BUFFER_TEST_SIZE);
    memset(bufferTest2, 0, BUFFER_TEST_SIZE);

    // create 1123 bytes buffer filled with the numbers 0..255
    for (uint32_t i = 0; i < BUFFER_TEST_SIZE; i++)
    {
        bufferTest[i] = (uint8_t)(i % 256);
    }
    res = pal_fsUnlink(addRootToPath(fileName,buffer,storageId));
    TEST_ASSERT((PAL_SUCCESS == res) || (PAL_ERR_FS_NO_FILE == res));

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    // split the writes
    res = pal_fsFwrite(&g_fd1, small_write_buffer, TEST_BUFFER_SMALL_SIZE, &num_bytes_write);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(TEST_BUFFER_SMALL_SIZE, num_bytes_write);

    res = pal_fsFwrite(&g_fd1, bufferTest, BUFFER_TEST_SIZE, &num_bytes_write);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(BUFFER_TEST_SIZE, num_bytes_write);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsFopen(addRootToPath(fileName,buffer,storageId), PAL_FS_FLAG_READONLY, &g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    // split the reads
    res = pal_fsFread(&g_fd1, small_read_buffer, TEST_BUFFER_SMALL_SIZE, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(TEST_BUFFER_SMALL_SIZE, num_bytes_read);

    res = pal_fsFread(&g_fd1, bufferTest2, BUFFER_TEST_SIZE, &num_bytes_read);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);
    TEST_ASSERT_EQUAL(BUFFER_TEST_SIZE, num_bytes_read);

    TEST_ASSERT_EQUAL_INT8_ARRAY(bufferTest, bufferTest2, BUFFER_TEST_SIZE);

    res = pal_fsFclose(&g_fd1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    res = pal_fsUnlink(addRootToPath(fileName,buffer,storageId));
    TEST_ASSERT_EQUAL(PAL_SUCCESS, res);

    free(bufferTest);
    bufferTest = NULL;
    free(bufferTest2);
    bufferTest2 = NULL;    
}

TEST(pal_fileSystem, SequentialWriteAndRead)
{
    SequentialWriteAndRead(PAL_FS_PARTITION_PRIMARY);
    SequentialWriteAndRead(PAL_FS_PARTITION_SECONDARY);
}
