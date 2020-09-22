/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
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

#ifndef NM_DYNMEM_API_H_
#define NM_DYNMEM_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef size_t nm_mem_block_size_t;

void *nm_dyn_mem_alloc(nm_mem_block_size_t alloc_size);
void nm_dyn_mem_free(void *block);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* NM_DYNMEM_API_H_ */
