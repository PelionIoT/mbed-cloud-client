/*
 * Copyright (c) 2019 ARM Limited. All rights reserved.
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

#ifndef MBED_CLIENT_WEAK__H
#define MBED_CLIENT_WEAK__H

// copied here from mbed_toolchain.h ...
#if defined(__ICCARM__)
#define MBED_CLIENT_WEAK_FUNCTION __weak
#elif defined(__MINGW32__)
#define MBED_CLIENT_WEAK_FUNCTION
#else
#define MBED_CLIENT_WEAK_FUNCTION __attribute__((weak))
#endif

#endif // #ifndef MBED_CLIENT_WEAK__H
