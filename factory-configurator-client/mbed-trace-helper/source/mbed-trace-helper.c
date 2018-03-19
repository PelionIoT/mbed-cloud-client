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

#include "pv_log.h"
#include <stdarg.h>
#include <inttypes.h>
#include <stdlib.h>
#include "pal.h"
#include "pv_error_handling.h"
#include "mbed-trace/mbed_trace.h"
/**
* Mutex for printing logs in a thread safe manner.
*/
palMutexID_t g_pv_logger_mutex = NULLPTR;

void mbed_trace_helper_print(const char* format)
{
    fprintf(stdout, "%s\n", format);
}

void mbed_trace_helper_mutex_wait()
{
    (void)pal_osMutexWait(g_pv_logger_mutex, PAL_RTOS_WAIT_FOREVER);
}

void mbed_trace_helper_mutex_release()
{
    (void)pal_osMutexRelease(g_pv_logger_mutex);
}
/**
* Creates mutex
*/
bool mbed_trace_helper_create_mutex(void)
{
    palStatus_t status;

    // g_pv_logger_mutex already created - no need to recreate it.
    if (g_pv_logger_mutex) {
        goto exit;
    }

    status = pal_osMutexCreate(&g_pv_logger_mutex);
    if (status != PAL_SUCCESS) {
        SA_PV_LOG_INFO("Error creating g_pv_logger_mutex (pal err = %d)", (int)status);
        return false;
    }

exit:
    return true;
}

/**
* Deletes mutex
*/
void mbed_trace_helper_delete_mutex(void)
{
    // g_pv_logger_mutex already created - no need to recreate it.
    if (g_pv_logger_mutex == NULLPTR) {
        return;
    }

    pal_osMutexDelete(&g_pv_logger_mutex);
    g_pv_logger_mutex = NULLPTR;
}

uint8_t mbed_trace_helper_check_activated_trace_level()
{
    uint8_t config_active_level = 0;
    uint8_t activated_level = 0;

    SA_PV_LOG_INFO_FUNC_ENTER("MBED_TRACE_MAX_LEVEL = %d", MBED_TRACE_MAX_LEVEL);

    config_active_level = mbed_trace_config_get() & TRACE_MASK_LEVEL;
    SA_PV_LOG_INFO("config_active_level is %d", config_active_level);
    
    activated_level = config_active_level & MBED_TRACE_MAX_LEVEL;
    SA_PV_LOG_INFO("activated_level is %d", activated_level);

    if (activated_level == 0) {
        SA_PV_LOG_CRITICAL("The compiled maximum trace level %d, is higher than activated trace level", MBED_TRACE_MAX_LEVEL);
        SA_PV_LOG_CRITICAL("If you want to use the requested log level, please change MBED_TRACE_MAX_LEVEL compilation flag and recompile the code");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return activated_level;
}

bool mbed_trace_helper_init(uint8_t config, bool is_mutex_used)
{
    bool success = true;
    int rc = 0;

    rc = mbed_trace_init();

    if (rc != 0) {
        return false;
    }

    if (is_mutex_used) {
        // Create mutex
        success = mbed_trace_helper_create_mutex();
        if (success != true) {
            mbed_trace_free();
            return false;
        }
    }
    // Set trace level, TRACE_MODE_PLAIN used to ignore mbed trace print pattern ([trace_level] [trace_group] format)
    mbed_trace_config_set(config);

    // Set trace print function
    mbed_trace_print_function_set(mbed_trace_helper_print);

    if (is_mutex_used) {
        // Set mutex wait function for mbed trace
        mbed_trace_mutex_wait_function_set(mbed_trace_helper_mutex_wait);
        // Set mutex release function for mbed trace
        mbed_trace_mutex_release_function_set(mbed_trace_helper_mutex_release);
    }
    return  true;
}

void mbed_trace_helper_finish()
{
    mbed_trace_helper_delete_mutex();
    mbed_trace_free();
}



