// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef __PV_LOG_H__
#define __PV_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#define __PV_LOG_H__INSIDE
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include "pal.h"
#include "mbed-trace/mbed_trace.h"

#define __SA_PV_FILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

extern palMutexID_t g_pv_logger_mutex;
/**
* Calls to mbed trace print function
*
* - The function sets mbed trace level according to log level, compose buffer with general data (line,color, file..) and message
* and calls to mbed_vtracef.
*/
void pv_log_trace(int level, const char* filename, int line, const char *func, const char *format, ...);
/**
* Print buffer with mbed trace function
*
*/
void pv_log_trace_buffer(int level, const char* filename, int line, const char *func, const char *color, const char *name, const uint8_t *buff, uint32_t buff_size);

#define _SA_PV_LOG_FUNC_ENTER(level, filename, line, func, format, ...) _SA_PV_LOG(level, filename, line, func, "===> " format, ##__VA_ARGS__)

/**  Exit function logging
 *
 * - Should be called in the end of a function, assuming the function doesn't exit early due to an error.
 * - Should display values of output variables (with meaning, no need to print buffers).
 * - Usage example (with INFO level): SA_PV_LOG_INFO_FUNC_EXIT("argPointerToInt = %d, argPointerToUnsigned32 = %" PRIu32 "", *argPointerToInt, (uint32_t)*argPointerToUnsigned32);
 */
#define _SA_PV_LOG_FUNC_EXIT(level, filename, line, func, format, ...) _SA_PV_LOG(level, filename, line, func, "<=== " format, ##__VA_ARGS__)

// CRITICAL always being output
#define SA_PV_LOG_CRITICAL(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_CMD, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_BYTE_BUFF_CRITICAL(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_CMD, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)
#define SA_PV_LOG_CRITICAL_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_CMD, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_ERROR)
#define SA_PV_LOG_ERR(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_ERROR, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_BYTE_BUFF_ERR(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_ERROR, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)
#define SA_PV_LOG_ERR_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_ERROR, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

#else
#define SA_PV_LOG_ERR(format, argargs...) do {} while (0)
#define SA_PV_LOG_BYTE_BUFF_ERR(format, argargs...) do {} while (0)
#define SA_PV_LOG_ERR_FUNC_EXIT(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_WARN)
#define SA_PV_LOG_WARN(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_WARN, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_BYTE_BUFF_WARN(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_WARN, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)
#define SA_PV_LOG_WARN_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_WARN, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#else
#define SA_PV_LOG_WARN(format, ...) do {} while (0)
#define SA_PV_LOG_BYTE_BUFF_WARN(format, ...) do {} while (0)
#define SA_PV_LOG_WARN_FUNC_EXIT(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_INFO)
#define SA_PV_LOG_INFO(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_INFO, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_INFO_FUNC_ENTER(format, ...) \
        _SA_PV_LOG_FUNC_ENTER(TRACE_LEVEL_INFO, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS() \
        SA_PV_LOG_INFO_FUNC_ENTER("")
#define SA_PV_LOG_INFO_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_INFO, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS() \
        SA_PV_LOG_INFO_FUNC_EXIT("")
#define SA_PV_LOG_BYTE_BUFF_INFO(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_INFO, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)
#else
#define SA_PV_LOG_INFO(format, ...) do {} while (0)
#define SA_PV_LOG_INFO_FUNC_ENTER(format, ...) do {} while (0)
#define SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SA_PV_LOG_INFO_FUNC_EXIT(format, ...) do {} while (0)
#define SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SA_PV_LOG_BYTE_BUFF_INFO(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG)
#define SA_PV_LOG_TRACE(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_TRACE_FUNC_ENTER(format, ...) \
        _SA_PV_LOG_FUNC_ENTER(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS() \
        SA_PV_LOG_TRACE_FUNC_ENTER("")
#define SA_PV_LOG_TRACE_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS() \
        SA_PV_LOG_TRACE_FUNC_EXIT("")
#define SA_PV_LOG_BYTE_BUFF_TRACE(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)

#else
#define SA_PV_LOG_TRACE(format, ...) do {} while (0)
#define SA_PV_LOG_TRACE_FUNC_ENTER(format, ...) do {} while (0)
#define SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SA_PV_LOG_TRACE_FUNC_EXIT(format, ...) do {} while (0)
#define SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SA_PV_LOG_BYTE_BUFF_TRACE(format, ...) do {} while (0)
#endif

#if (MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG)
#define SA_PV_LOG_DATA(format, ...) \
        _SA_PV_LOG(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_DATA_FUNC_ENTER(format, ...) \
  _SA_PV_LOG_FUNC_ENTER(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_DATA_FUNC_ENTER_NO_ARGS() \
        SA_PV_LOG_DATA_FUNC_ENTER("")
#define SA_PV_LOG_DATA_FUNC_EXIT(format, ...) \
        _SA_PV_LOG_FUNC_EXIT(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define SA_PV_LOG_DATA_FUNC_EXIT_NO_ARGS() \
        SA_PV_LOG_DATA_FUNC_EXIT("")
#define SA_PV_LOG_BYTE_BUFF_DATA(name, buff, buff_size) \
        _SA_PV_BYTE_BUFF_LOG(TRACE_LEVEL_DEBUG, __SA_PV_FILE__, __LINE__, __func__, name, buff, buff_size)
#else
#define SA_PV_LOG_DATA(format, ...) do {} while (0)
#define SA_PV_LOG_DATA_FUNC_ENTER(format, ...) do {} while (0)
#define SA_PV_LOG_DATA_FUNC_ENTER_NO_ARGS() do {} while (0)
#define SA_PV_LOG_DATA_FUNC_EXIT(format, ...) do {} while (0)
#define SA_PV_LOG_DATA_FUNC_EXIT_NO_ARGS() do {} while (0)
#define SA_PV_LOG_BYTE_BUFF_DATA(format, ...) do {} while (0)
#endif

/* Should only be called once, additional calls do nothing. */
#define _SA_PV_LOG(level, file, line, func, format, ...) \
do{ \
        mbed_tracef(level, "fcc","%s:%d:%s:" format, file, line, func, ##__VA_ARGS__);\
} while (0)

#define _SA_PV_BYTE_BUFF_LOG(level, file, line, func, name, buff, buff_size) ( mbed_tracef(level, "fcc", "%s"name, mbed_trace_array(buff, buff_size)))

#undef __PV_LOG_H__INSIDE

#ifdef __cplusplus
}
#endif
#endif /*__PV_LOG_H__*/

