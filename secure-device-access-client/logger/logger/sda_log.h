// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

/* Logging macros */

#ifndef __SDA_LOG_H__
#define __SDA_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#define __SDA_LOG_H__INSIDE
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include "pal.h"
#include "mbed-trace/mbed_trace.h"



#define SDA_LOG_LEVEL_CRITICAL_COLOR  "\x1B[31m" /* red */
#define SDA_LOG_LEVEL_ERR_COLOR	"\x1B[31m" /* red */
#define SDA_LOG_LEVEL_WARN_COLOR	"\x1B[33m" /* yellow */
#define SDA_LOG_LEVEL_INFO_COLOR      "\x1B[0m"  /* normal */
#define SDA_LOG_LEVEL_TRACE_COLOR     "\x1B[0m"  /* normal */
#define SDA_LOG_LEVEL_DATA_COLOR      "\x1B[37m" /* white */


#define __SDA_FILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

extern palMutexID_t g_sda_logger_mutex;
/**
* Calls to mbed trace print function
*
* - The function sets mbed trace level according to log level, compose buffer with general data (line,color, file..) and message
* and calls to mbed_vtracef.
*/
void sda_log_trace(int level, const char* filename, int line, const char *func, const char *color, const char *format, ...);
/**
* Print buffer with mbed trace function
*
*/
void sda_log_trace_buffer(int level, const char* filename, int line, const char *func, const char *color, const char *name, const uint8_t *buff, uint32_t buff_size);

#define _SDA_LOG_FUNC_ENTER(level, filename, line, func, color, format, ...) _SDA_LOG(level, filename, line, func, color, "===> " format, ##__VA_ARGS__)

/**  Exit function logging
 *
 * - Should be called in the end of a function, assuming the function doesn't exit early due to an error.
 * - Should display values of output variables (with meaning, no need to print buffers).
 * - Usage example (with INFO level): SDA_LOG_INFO_FUNC_EXIT("argPointerToInt = %d, argPointerToUnsigned32 = %" PRIu32 "", *argPointerToInt, (uint32_t)*argPointerToUnsigned32);
 */
#define _SDA_LOG_FUNC_EXIT(level, filename, line, func, color, format, ...) _SDA_LOG(level, filename, line, func, color, "<=== " format, ##__VA_ARGS__)

// CRITICAL always being output
#define SDA_LOG_CRITICAL(format, ...) \
        _SDA_LOG(TRACE_LEVEL_CMD, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_CRITICAL_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_BYTE_BUFF_CRITICAL(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_CMD, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_CRITICAL_COLOR, name, buff, buff_size)
#define SDA_LOG_CRITICAL_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_CMD, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_CRITICAL_COLOR, format, ##__VA_ARGS__)

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_ERROR) && !defined(SDA_TRACE_DEMO)
#define SDA_LOG_ERR(format, ...) \
        _SDA_LOG(TRACE_LEVEL_ERROR, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_ERR_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_BYTE_BUFF_ERR(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_ERROR, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_ERR_COLOR, name, buff, buff_size)
#define SDA_LOG_ERR_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_ERROR, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_ERR_COLOR, format, ##__VA_ARGS__)

#else
#define SDA_LOG_ERR(format, arg...) do {} while (0)
#define SDA_LOG_BYTE_BUFF_ERR(format, arg...) do {} while (0)
#define SDA_LOG_ERR_FUNC_EXIT(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_WARN) && !defined(SDA_TRACE_DEMO)
#define SDA_LOG_WARN(format, ...) \
        _SDA_LOG(TRACE_LEVEL_WARN, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_WARN_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_BYTE_BUFF_WARN(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_WARN, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_WARN_COLOR, name, buff, buff_size)
#define SDA_LOG_WARN_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_WARN, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_WARN_COLOR, format, ##__VA_ARGS__)
#else
#define SDA_LOG_WARN(format, ...) do {} while (0)
#define SDA_LOG_BYTE_BUFF_WARN(format, ...) do {} while (0)
#define SDA_LOG_WARN_FUNC_EXIT(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_INFO) && !defined(SDA_TRACE_DEMO)
#define SDA_LOG_INFO(format, ...) \
        _SDA_LOG(TRACE_LEVEL_INFO, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_INFO_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_INFO_FUNC_ENTER(format, ...) \
        _SDA_LOG_FUNC_ENTER(TRACE_LEVEL_INFO, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_INFO_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_INFO_FUNC_ENTER_NO_ARGS() \
        SDA_LOG_INFO_FUNC_ENTER("")
#define SDA_LOG_INFO_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_INFO, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_INFO_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_INFO_FUNC_EXIT_NO_ARGS() \
        SDA_LOG_INFO_FUNC_EXIT("")
#define SDA_LOG_BYTE_BUFF_INFO(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_INFO, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_INFO_COLOR, name, buff, buff_size)
#else
#define SDA_LOG_INFO(format, ...) do {} while (0)
#define SDA_LOG_INFO_FUNC_ENTER(format, ...) do {} while (0)
#define SDA_LOG_INFO_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SDA_LOG_INFO_FUNC_EXIT(format, ...) do {} while (0)
#define SDA_LOG_INFO_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SDA_LOG_BYTE_BUFF_INFO(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG) && !defined(SDA_TRACE_DEMO)
#define SDA_LOG_TRACE(format, ...) \
        _SDA_LOG(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_TRACE_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_TRACE_FUNC_ENTER(format, ...) \
        _SDA_LOG_FUNC_ENTER(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_TRACE_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS() \
        SDA_LOG_TRACE_FUNC_ENTER("")
#define SDA_LOG_TRACE_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_TRACE_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS() \
        SDA_LOG_TRACE_FUNC_EXIT("")
#define SDA_LOG_BYTE_BUFF_TRACE(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_TRACE_COLOR, name, buff, buff_size)

#else
#define SDA_LOG_TRACE(format, ...) do {} while (0)
#define SDA_LOG_TRACE_FUNC_ENTER(format, ...) do {} while (0)
#define SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SDA_LOG_TRACE_FUNC_EXIT(format, ...) do {} while (0)
#define SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SDA_LOG_BYTE_BUFF_TRACE(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG) && !defined(SDA_TRACE_DEMO)
#define SDA_LOG_DATA(format, ...) \
        _SDA_LOG(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_DATA_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_DATA_FUNC_ENTER(format, ...) \
  _SDA_LOG_FUNC_ENTER(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_DATA_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_DATA_FUNC_ENTER_NO_ARGS() \
        SDA_LOG_DATA_FUNC_ENTER("")
#define SDA_LOG_DATA_FUNC_EXIT(format, ...) \
        _SDA_LOG_FUNC_EXIT(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_DATA_COLOR, format, ##__VA_ARGS__)
#define SDA_LOG_DATA_FUNC_EXIT_NO_ARGS() \
        SDA_LOG_DATA_FUNC_EXIT("")
#define SDA_LOG_BYTE_BUFF_DATA(name, buff, buff_size) \
        _SDA_BYTE_BUFF_LOG(TRACE_LEVEL_DEBUG, __SDA_FILE__, __LINE__, __func__, SDA_LOG_LEVEL_DATA_COLOR, name, buff, buff_size)
#else
#define SDA_LOG_DATA(format, ...) do {} while (0)
#define SDA_LOG_DATA_FUNC_ENTER(format, ...) do {} while (0)
#define SDA_LOG_DATA_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SDA_LOG_DATA_FUNC_EXIT(format, ...) do {} while (0)
#define SDA_LOG_DATA_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SDA_LOG_BYTE_BUFF_DATA(format, ...) do {} while (0)
#endif

#ifdef SDA_TRACE_DEMO
#define SDA_LOG_DEMO_INFO(format, ...) \
do{ \
        mbed_tracef(TRACE_LEVEL_INFO, "sda", SDA_LOG_LEVEL_INFO_COLOR format SDA_LOG_LEVEL_INFO_COLOR, ##__VA_ARGS__); \
} while (0)
#define SDA_LOG_DEMO_ERROR(format, ...) \
do{ \
        mbed_tracef(TRACE_LEVEL_ERROR, "sda", SDA_LOG_LEVEL_ERR_COLOR format SDA_LOG_LEVEL_INFO_COLOR, ##__VA_ARGS__); \
} while (0)

#define SDA_DEMO_CHECK_ERROR(cond, format, ...) \
        if ((cond)) { \
            SDA_LOG_DEMO_ERROR(format, ##__VA_ARGS__); \
        }

#else
#define SDA_LOG_DEMO_INFO(format, ...) do {} while (0)
#define SDA_LOG_DEMO_ERROR(format, ...) do {} while (0)
#define SDA_DEMO_CHECK_ERROR(format, ...) do {} while (0)
#endif

/* Should only be called once, additional calls do nothing. */
#define _SDA_LOG(level, file, line, func, color, format, ...) \
do{ \
        mbed_tracef(level, "sda", "%s%s:%d:%s:"format,color, file, line, func, ##__VA_ARGS__);\
} while (0)



#define _SDA_BYTE_BUFF_LOG(level, file, line, func, color, name, buff, buff_size) \
do{ \
    mbed_tracef(level, "sda", name " %s", mbed_trace_array(buff, buff_size)); \
} while (0)

#undef __SDA_LOG_H__INSIDE

#ifdef __cplusplus
}
#endif
#endif /*__SDA_LOG_H__*/

