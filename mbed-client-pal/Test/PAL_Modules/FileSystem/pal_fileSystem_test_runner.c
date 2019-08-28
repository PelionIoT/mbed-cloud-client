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

#include "unity.h"
#include "unity_fixture.h"
#include "pal.h"

TEST_GROUP_RUNNER(pal_fileSystem)
{
    RUN_TEST_CASE(pal_fileSystem, SDFormat);
	RUN_TEST_CASE(pal_fileSystem, rootDirectoryTests);
	RUN_TEST_CASE(pal_fileSystem, directoryTests);
	RUN_TEST_CASE(pal_fileSystem, FilesTests);
	RUN_TEST_CASE(pal_fileSystem, FilesTestsSeek);
	RUN_TEST_CASE(pal_fileSystem, FilesPermission_read_only);
	RUN_TEST_CASE(pal_fileSystem, FilesPermission_read_write);
	RUN_TEST_CASE(pal_fileSystem, FilesPermission_read_write_trunc);
	RUN_TEST_CASE(pal_fileSystem, create_write_and_read_pal_file);
    RUN_TEST_CASE(pal_fileSystem, WriteInTheMiddle);
    RUN_TEST_CASE(pal_fileSystem, SequentialWriteAndRead);
}
