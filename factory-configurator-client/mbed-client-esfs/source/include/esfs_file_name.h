/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __ESFS_FILE_NAME_H
#define __ESFS_FILE_NAME_H

#ifdef __cplusplus
extern "C" {
#endif

esfs_result_e esfs_get_name_from_blob(const uint8_t *blob, uint32_t blob_length,char *file_name, uint32_t size_of_file_name);


#ifdef __cplusplus
}
#endif


#endif


