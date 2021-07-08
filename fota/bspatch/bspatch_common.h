// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef DELTA_TOOL_INTERNAL_INCLUDE_COMMON_H_
#define DELTA_TOOL_INTERNAL_INCLUDE_COMMON_H_

#define FILE_MAGIC "PELION/BSDIFF001"  // BSDIFF version
#define FILE_MAGIC_LEN (sizeof(FILE_MAGIC) - 1)  // without the null termination

#define MAX_FRAME_SIZE_DEFAULT 512

#endif /* DELTA_TOOL_INTERNAL_INCLUDE_COMMON_H_ */
