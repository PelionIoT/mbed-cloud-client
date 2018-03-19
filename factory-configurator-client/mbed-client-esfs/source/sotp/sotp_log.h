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


#ifndef __SOTP_LOG_H
#define __SOTP_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#if 0
#if defined(ESFS_INTERACTIVE_TEST) && defined(TARGET_IS_PC_LINUX)
    #ifndef SOTP_LOG
        #define SOTP_LOG 1
    #endif
#endif
#endif

#if SOTP_LOG
void sotp_log_create(char *fmt, ...);
void sotp_log_append(char *fmt, ...);
void sotp_log_finalize(void);
void sotp_log_init(void);
void sotp_log_print_log(void);
#define SOTP_LOG_CREATE sotp_log_create
#define SOTP_LOG_APPEND sotp_log_append
#define SOTP_LOG_FINALIZE sotp_log_finalize
#define SOTP_LOG_PRINT_LOG sotp_log_print_log
#define SOTP_LOG_INIT sotp_log_init
#else
#define SOTP_LOG_CREATE(...) ((void)0)
#define SOTP_LOG_APPEND(...) ((void)0)
#define SOTP_LOG_FINALIZE(...) ((void)0)
#define SOTP_LOG_PRINT_LOG(...) ((void)0)
#define SOTP_LOG_INIT(...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif

