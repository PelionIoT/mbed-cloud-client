/*
 * Copyright (c) 2021 Pelion. All rights reserved.
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

#include <string.h>
#include <stdio.h>

#include "m2mdynlog.h"
#include "m2minterfacefactory.h"
#include "mbed-trace/mbed-trace/mbed_trace.h"
#include "eventOS_scheduler.h"
#include "CloudClientStorage.h"
#include "common_functions.h"
#include "fota/fota_block_device.h"
#include "fota/fota_candidate.h"
#include "fota/fota.h"

#if defined (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE) && (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE > 0)

#ifdef MBED_CLIENT_DYNAMIC_TRACE_ENABLE
#define DYNLOG_TRACE(fmt, ...)  printf("" fmt "\n", ##__VA_ARGS__)
#else
#define DYNLOG_TRACE(fmt, ...)
#endif // MBED_CLIENT_DYNAMIC_TRACE_ENABLE

#define TRACE_GROUP "mClt"
#define DYNLOG_OBJECT_ID "33456"

#define ERROR_STRING "[ERR ]"
#define WARN_STRING "[WARN]"

#define SEND_ERASE_EVENT 1
#define SEND_START_CAPTURE_EVENT 2
#define SEND_STOP_CAPTURE_EVENT 3
#define SEND_STORE_EVENT 4

const char *read_offset_key = "mbed.read_offset";
const char *write_offset_key = "mbed.write_offset";
const char *logging_enabled_key = "mbed.logging_enabled";
const char *trace_level_key = "mbed.trace_level";
const char *trace_level_trigger_key = "mbed.trace_level_trigger";

static palMutexID_t trace_mutex_id = 0;
static palMutexID_t mutex_id = 0;
M2MDynLog *M2MDynLog::_instance = NULL;

void M2MDynLog::dynlog_trace_mutex_wait()
{
    palStatus_t status;
    status = pal_osMutexWait(trace_mutex_id, UINT32_MAX);
    assert(PAL_SUCCESS == status);
    (void) status;
}

void M2MDynLog::dynlog_trace_mutex_release()
{
    palStatus_t status;
    status = pal_osMutexRelease(trace_mutex_id);
    assert(PAL_SUCCESS == status);
    (void) status;
}

void M2MDynLog::dynlog_mutex_wait()
{
    palStatus_t status;
    status = pal_osMutexWait(mutex_id, UINT32_MAX);
    assert(PAL_SUCCESS == status);
    (void) status;
}

void M2MDynLog::dynlog_mutex_release()
{
    palStatus_t status;
    status = pal_osMutexRelease(mutex_id);
    assert(PAL_SUCCESS == status);
    (void) status;
}

void M2MDynLog::dynamic_log_tasklet(struct arm_event_s *event)
{
    event->sender = 0;

    if (SEND_ERASE_EVENT == event->event_type) {
        M2MDynLog::get_instance()->erase_logs();
    } else if (SEND_STOP_CAPTURE_EVENT == event->event_type) {
        M2MDynLog::get_instance()->stop(event->event_id, event->event_data);
    } else if (SEND_START_CAPTURE_EVENT == event->event_type) {
        M2MDynLog::get_instance()->start();
    } else if (SEND_STORE_EVENT == event->event_type) {
        M2MDynLog::get_instance()->store(event->data_ptr);
    }
}

void M2MDynLog::trace_level_updated_cb(const char */*object_name*/)
{
    M2MDynLog::get_instance()->store_trace_levels_to_kcm();
}

void M2MDynLog::start_logging_cb(void */*args*/)
{
    M2MDynLog::get_instance()->start_capture();
}

void M2MDynLog::stop_logging_cb(void */*args*/)
{
    M2MDynLog::get_instance()->stop_capture(true, false);
}

void M2MDynLog::clear_logs_cb(void */*args*/)
{
    M2MDynLog::get_instance()->clear();
}

void M2MDynLog::clear()
{
    if (!fota_is_active_update()) {
        if (!_event.data.sender) {
            _event.data.sender = 1;
            _event.data.event_type = SEND_ERASE_EVENT;
            eventOS_event_send_user_allocated(&_event);
        } else {
            DYNLOG_TRACE("clear - event already in queue");
        }
    }
}

coap_response_code_e M2MDynLog::log_read_requested(const M2MResourceBase &resource,
                                                   uint8_t *&buffer,
                                                   size_t &buffer_size,
                                                   size_t &total_size,
                                                   const size_t offset,
                                                   void *client_args)
{
    return M2MDynLog::get_instance()->handle_read_request(resource, buffer, buffer_size, total_size, offset, client_args);
}

extern "C" void trace_output(const char *str)
{
    M2MDynLog::get_instance()->handle_trace_output(str);
}

M2MDynLog::M2MDynLog()
    : _capture_ongoing(false),
      _keyword_found(false),
      _initialized(false),
      _tasklet_id(-1),
      _total_log_size(0),
      _write_offset(0),
      _read_offset(0),
      _prog_size(0),
      _log_chunk(NULL),
      _mem_book(NULL),
      _trace_level_res(NULL),
      _trace_level_trigger_res(NULL),
      _nvm_size(NULL),
      _erase_on_full_res(NULL),
      _logging_enabled_res(NULL),
      _unread_log_size(NULL),
      _error_res(NULL),
      _total_log_size_res(NULL)
{
    ns_list_init(&_trace_list);
}

M2MDynLog::~M2MDynLog()
{
    mbed_trace_mutex_wait_function_set(NULL);
    mbed_trace_mutex_release_function_set(NULL);
    mbed_trace_print_function_set(NULL);

    free(_log_chunk);
    free_trace_list();
    pal_osMutexDelete(&trace_mutex_id);
    pal_osMutexDelete(&mutex_id);
}

M2MDynLog *M2MDynLog::get_instance()
{
    if (_instance == NULL) {
        _instance = new M2MDynLog();
    }
    return _instance;
}

void M2MDynLog::delete_instance()
{
    delete _instance;
    _instance = NULL;
}

int8_t M2MDynLog::get_trace_level() const
{
    int8_t trace_level = -1;
    if (_trace_level_res) {
        trace_level = _trace_level_res->get_value_int();
    }

    switch (trace_level) {
        case 0:
            return TRACE_ACTIVE_LEVEL_CMD;
        case 1:
            return TRACE_ACTIVE_LEVEL_ERROR;
        case 2:
            return TRACE_ACTIVE_LEVEL_WARN;
        case 3:
            return TRACE_ACTIVE_LEVEL_INFO;
        case 4:
            return TRACE_ACTIVE_LEVEL_DEBUG;
        default:
            return TRACE_ACTIVE_LEVEL_NONE;
    }
}

int8_t M2MDynLog::get_default_trace_level() const
{
    uint8_t buf[2] = {0};
    size_t size = 0;

    if (kcm_get(trace_level_key, buf, 2, &size)) {
        return common_read_16_bit(buf);
    }

    switch (MBED_TRACE_MAX_LEVEL) {
        case TRACE_LEVEL_DEBUG:
            return 4;
        case TRACE_LEVEL_INFO:
            return 3;
        case TRACE_LEVEL_WARN:
            return 2;
        case TRACE_LEVEL_ERROR:
            return 1;
        case TRACE_LEVEL_CMD:
            return 0;
        default:
            return 1;
    }
}

void M2MDynLog::stop_capture(bool stopped_by_user, bool stopped_by_update)
{
    if (!_event.data.sender) {
        _event.data.sender = 1;
        _event.data.event_type = SEND_STOP_CAPTURE_EVENT;
        _event.data.event_id = stopped_by_user;
        _event.data.event_data = stopped_by_update;
        eventOS_event_send_user_allocated(&_event);
    } else {
        DYNLOG_TRACE("stop_capture - event already in queue");
    }
}

void M2MDynLog::stop(bool stopped_by_user, bool stopped_by_update)
{
    DYNLOG_TRACE("stop - initialized: %d, capturing: %d, stopped by user: %d, aborted: %d", _initialized, _capture_ongoing, stopped_by_user, stopped_by_update);

    if (!_initialized || !_capture_ongoing) {
        return;
    }

    _capture_ongoing = false;

    if (stopped_by_user) {
        store_to_nvm(NULL);
    }

    if (stopped_by_update) {
        _error_res->set_value(DYNLOG_ERROR_ABORTED);
    }

    _logging_enabled_res->set_value(_capture_ongoing);
    uint8_t buf[2] = {0};
    common_write_16_bit(_capture_ongoing, buf);
    kcm_set(logging_enabled_key, buf, 2);

    mbed_trace_print_function_set(NULL);
}
void M2MDynLog::start_capture()
{
    if (!_event.data.sender) {
        _event.data.sender = 1;
        _event.data.event_type = SEND_START_CAPTURE_EVENT;
        eventOS_event_send_user_allocated(&_event);
    } else {
        DYNLOG_TRACE("start_capture - event already in queue");
    }
}
void M2MDynLog::start()
{
    DYNLOG_TRACE("start - initialized: %d, capturing: %d", _initialized, _capture_ongoing);
    if (!_initialized || _capture_ongoing) {
        return;
    }

    if (fota_is_active_update() /*|| is_fota_deferred()*/) {
        DYNLOG_TRACE("FOTA is active, ignore start");
        _error_res->set_value(DYNLOG_ERROR_ABORTED);
        return;
    }

    _capture_ongoing = true;
    _logging_enabled_res->set_value(_capture_ongoing);
    uint8_t buf[2] = {0};
    common_write_16_bit(_capture_ongoing, buf);
    kcm_set(logging_enabled_key, buf, 2);

    // Clear any existing errors
    _error_res->set_value(DYNLOG_SUCCESS);

    DYNLOG_TRACE("trace level: %" PRId64 ", trace level trigger: %" PRId64, _trace_level_res->get_value_int(), _trace_level_trigger_res->get_value_int());

    mbed_trace_mutex_wait_function_set(dynlog_trace_mutex_wait);
    mbed_trace_mutex_release_function_set(dynlog_trace_mutex_release);
    mbed_trace_print_function_set(trace_output);
    mbed_trace_config_set(get_trace_level());
}

bool M2MDynLog::initialize(M2MBaseList &objects, const int8_t tasklet_id)
{
    if (_initialized) {
        return true;
    }

    palStatus_t status = pal_osMutexCreate(&trace_mutex_id);
    assert(PAL_SUCCESS == status);

    status = pal_osMutexCreate(&mutex_id);
    assert(PAL_SUCCESS == status);

    _tasklet_id = tasklet_id;
    _event.data.data_ptr = NULL;
    _event.data.event_data = 0;
    _event.data.event_id = 0;
    _event.data.sender = 0;
    _event.data.event_type = 0;
    _event.data.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    _event.data.receiver = M2MDynLog::_tasklet_id;

    _mem_book = ns_mem_init(_trace_buffer, MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE, NULL, NULL);
    assert(_mem_book);

    read_defaults_from_kcm();

    if (!create_resources(objects)) {
        return false;
    }

    if (fota_bd_init() != FOTA_STATUS_SUCCESS) {
        return false;
    }

    fota_bd_get_program_size(&_prog_size);

    _initialized = true;

    // start capture automatically if set in KCM
    if (_capture_ongoing) {
        _capture_ongoing = false;
        start_capture();
    }

    return true;
}

bool M2MDynLog::create_resources(M2MBaseList &objects)
{
    M2MObjectInstance *object_inst = NULL;
    M2MObject *object = NULL;

    object = M2MInterfaceFactory::create_object(DYNLOG_OBJECT_ID);
    if (object) {
        object->set_register_uri(false);
        object_inst = object->create_object_instance();
    } else {
        tr_error("M2MDynLog::create_resources - failed to create object!");
        return false;
    }

    if (object_inst) {
        object_inst->set_register_uri(false);

        M2MResource *res = object_inst->create_dynamic_resource("1", "", M2MResourceInstance::INTEGER, false);
        if (!res) {
            goto cleanup;
        }
        res->set_operation(M2MBase::POST_ALLOWED);
        res->set_execute_function(start_logging_cb);

        res = object_inst->create_dynamic_resource("2", "", M2MResourceInstance::INTEGER, false);
        if (!res) {
            goto cleanup;
        }
        res->set_operation(M2MBase::POST_ALLOWED);
        res->set_execute_function(stop_logging_cb);

        res = object_inst->create_dynamic_resource("3", "", M2MResourceInstance::STRING, false);
        if (!res) {
            goto cleanup;
        }
        res->set_operation(M2MBase::GET_ALLOWED);
        res->set_read_resource_function(log_read_requested, this);

        res = object_inst->create_dynamic_resource("4", "", M2MResourceInstance::INTEGER, false);
        if (!res) {
            goto cleanup;
        }
        res->set_operation(M2MBase::POST_ALLOWED);
        res->set_execute_function(clear_logs_cb);

        _trace_level_res = object_inst->create_dynamic_resource("5", "", M2MResourceInstance::INTEGER, false);
        if (!_trace_level_res) {
            goto cleanup;
        }
        _trace_level_res->set_operation(M2MBase::GET_PUT_ALLOWED);
        _trace_level_res->set_value(get_default_trace_level());
        _trace_level_res->set_value_updated_function(trace_level_updated_cb);

        _trace_level_trigger_res = object_inst->create_dynamic_resource("6", "", M2MResourceInstance::INTEGER, false);
        if (!_trace_level_trigger_res) {
            goto cleanup;
        }
        _trace_level_trigger_res->set_operation(M2MBase::GET_PUT_ALLOWED);
        _trace_level_trigger_res->set_value_updated_function(trace_level_updated_cb);
        uint8_t buf[2] = {0};
        size_t size = 0;
        if (kcm_get(trace_level_trigger_key, buf, 2, &size)) {
            _trace_level_trigger_res->set_value(common_read_16_bit(buf));
        } else {
            _trace_level_trigger_res->set_value(1); // Error level trigger by default
        }

        _nvm_size = object_inst->create_dynamic_resource("7", "", M2MResourceInstance::INTEGER, false);
        if (!_nvm_size) {
            goto cleanup;
        }
        _nvm_size->set_operation(M2MBase::GET_PUT_ALLOWED);
        // Use whole update image space
        _nvm_size->set_value(fota_candidate_get_config()->storage_size);

        _erase_on_full_res = object_inst->create_dynamic_resource("8", "", M2MResourceInstance::INTEGER, false);
        if (!_erase_on_full_res) {
            goto cleanup;
        }
        _erase_on_full_res->set_operation(M2MBase::GET_PUT_ALLOWED);
        _erase_on_full_res->set_value(0); // Disabled by default

        _logging_enabled_res = object_inst->create_dynamic_resource("9", "", M2MResourceInstance::BOOLEAN, true);
        if (!_logging_enabled_res) {
            goto cleanup;
        }
        _logging_enabled_res->set_operation(M2MBase::GET_ALLOWED);
        _logging_enabled_res->set_value(_capture_ongoing);

        _unread_log_size = object_inst->create_dynamic_resource("10", "", M2MResourceInstance::INTEGER, true);
        if (!_unread_log_size) {
            goto cleanup;
        }
        _unread_log_size->set_operation(M2MBase::GET_ALLOWED);
        _unread_log_size->set_value(_write_offset - _read_offset);

        _error_res = object_inst->create_dynamic_resource("11", "", M2MResourceInstance::INTEGER, true);
        if (!_error_res) {
            goto cleanup;
        }

        _error_res->set_operation(M2MBase::GET_ALLOWED);
        _error_res->set_value(DYNLOG_SUCCESS);

        _total_log_size_res = object_inst->create_dynamic_resource("12", "", M2MResourceInstance::INTEGER, true);
        if (!_total_log_size_res) {
            goto cleanup;
        }

        _total_log_size_res->set_operation(M2MBase::GET_ALLOWED);
        _total_log_size_res->set_value(_write_offset - fota_candidate_get_config()->storage_start_addr);

        objects.push_back(object);
    } else {
        tr_error("M2MDynLog::create_resources - failed to create res!");
        goto cleanup;
    }

    return true;

cleanup:
    delete object;
    return false;
}

void M2MDynLog::handle_trace_output(const char *str)
{
    // For debugging purposes
    DYNLOG_TRACE("%s", str);

    // Skip processing if capture is not enabled
    if (!_capture_ongoing) {
        return;
    }

    // If keyword trigger is not set store all lines to buffer and flush when buffer is full.
    // When keyword is set but not detected store trace line into list. If list is full remove first item and try to store again.
    // When keyword is set and detected write current line and whatever is in the list + next full buffer.
    bool save_all_mode = true;
    bool keyword_line_detected = false;

    int trigger_level = _trace_level_trigger_res->get_value_int();

    // Check if line contains a keyword
    if (trigger_level != 0) {
        save_all_mode = false;
        if (trigger_level == 1) {
            if (strstr(str, ERROR_STRING) != NULL) {
                keyword_line_detected = true;
            }
        } else {
            if (strstr(str, ERROR_STRING) != NULL || strstr(str, WARN_STRING) != NULL) {
                keyword_line_detected = true;
            }
        }
    }

    // force to "save all mode" if trace level trigger is active and triggered
    if (trigger_level != 0 && _keyword_found) {
        save_all_mode = true;
    }

    M2MDynLog::trace_list_s *item = (M2MDynLog::trace_list_s *)ns_mem_alloc(_mem_book, sizeof(M2MDynLog::trace_list_s));
    if (!item) {
        if (save_all_mode) {
            DYNLOG_TRACE("Failed to allocate list item - store buffer + current line to NVM ");
            store_to_nvm(str);
            _keyword_found = false;
            return;
        } else {
            DYNLOG_TRACE("Failed to allocate list item - remove item from list and try alloc again");
            ns_list_foreach_safe(M2MDynLog::trace_list_s, tmp, &_trace_list) {
                free_trace_list_item(tmp);
                item = (M2MDynLog::trace_list_s *)ns_mem_alloc(_mem_book, sizeof(M2MDynLog::trace_list_s));
                if (item) {
                    break;
                }
            }
        }
    }

    // Can happen if buffer is set too small, should we have min level limit?
    assert(item);

    size_t len = strlen(str) + 2;
    if (_prog_size > len) {
        len = _prog_size;
    }

    item->trace_line = (char *)ns_mem_alloc(_mem_book, len);
    if (!item->trace_line) {
        // Memory limit reached, store to NVM
        if (save_all_mode) {
            DYNLOG_TRACE("trace line alloc failed - save all");
            store_to_nvm(str);
            ns_mem_free(_mem_book, item);

            // clear the flag now since buffer is stored --> waiting for next keyword line
            _keyword_found = false;
        } else {
            if (keyword_line_detected) {
                DYNLOG_TRACE("trace line alloc failed - keyword found --> store");
                _keyword_found = true;
                store_to_nvm(str);
                ns_mem_free(_mem_book, item);
            } else {
                ns_list_foreach_safe(M2MDynLog::trace_list_s, tmp, &_trace_list) {
                    // Release enough memory to store current line
                    free_trace_list_item(tmp);
                    item->trace_line = (char *)ns_mem_alloc(_mem_book, len);
                    if (item->trace_line) {
                        memset(item->trace_line, 0, len); // fill whole storage block
                        store_to_ram(str, item);
                        break;
                    }
                }

                if (!item->trace_line) {
                    ns_mem_free(_mem_book, item);
                }
            }
        }
    } else {

        // Current line contains keyword([INFO]...), store everything what is in buffer
        if (keyword_line_detected) {
            // Save all lines until buffer is full
            DYNLOG_TRACE("Keyword found");
            store_to_nvm(str);

            _keyword_found = true;

            ns_mem_free(_mem_book, item->trace_line);
            ns_mem_free(_mem_book, item);
        } else {
            memset(item->trace_line, 0, len); // fill whole storage block
            store_to_ram(str, item);
        }
    }
}

void M2MDynLog::store_to_nvm(const char *str)
{
    M2MDynLog::ErrorStatus status = DYNLOG_SUCCESS;

    DYNLOG_TRACE("Store to NVM");

    if (!_event.data.sender) {
        uint8_t *buf = NULL;
        if (str) {
            size_t alloc_len = strlen(str) + 2;
            size_t str_len = strlen(str);
            if (_prog_size > alloc_len) {
                alloc_len = _prog_size;
            }

            buf = (uint8_t *)malloc(alloc_len);
            if (!buf) {
                _error_res->set_value(DYNLOG_ERROR_OUT_OF_MEMORY);
                status = DYNLOG_ERROR_OUT_OF_MEMORY;
            } else {
                memset(buf, 0, alloc_len);
                memcpy(buf, str, str_len);
                buf[str_len] = '\n';
                buf[str_len + 1] = '\0';
            }
        }

        _event.data.sender = 1;
        _event.data.event_type = SEND_STORE_EVENT;
        _event.data.data_ptr = buf;
        eventOS_event_send_user_allocated(&_event);
    } else {
        DYNLOG_TRACE("store - event already in queue");
    }
}

coap_response_code_e M2MDynLog::handle_read_request(const M2MResourceBase &/*resource*/,
                                                    uint8_t *&buffer,
                                                    size_t &buffer_size,
                                                    size_t &total_size,
                                                    const size_t offset,
                                                    void */*client_args*/)
{
    bool last_block_response = false;

    // First GET request
    if (offset == 0) {
        _total_log_size = 0;
        if (_read_offset != _write_offset) {
            _total_log_size = _write_offset - _read_offset;
        }
        DYNLOG_TRACE("handle_read_request - total log size: %" PRIu32, (uint32_t)_total_log_size);
    }

    // Do not process if file is empty
    if (_total_log_size == 0) {
        // Nothing to read
        goto cleanup;
    }

    // Allocate space for payload buffer
    free(_log_chunk);
    _log_chunk = (uint8_t *)malloc(buffer_size);
    if (!_log_chunk) {
        stop_capture(false, false);
        _error_res->set_value(DYNLOG_ERROR_OUT_OF_MEMORY);
        goto cleanup;
    }

    // Fits into single transaction
    if (_total_log_size <= buffer_size) {
        last_block_response = true;
    }
    // Adjust size of last package
    else if (offset + buffer_size >= _total_log_size) {
        buffer_size = _total_log_size - offset;
        last_block_response = true;
    }

    DYNLOG_TRACE("handle_read_request - read %" PRIu32" bytes starting from address 0x%zx", (uint32_t)buffer_size, _read_offset);

    if (fota_bd_read((void *)_log_chunk, _read_offset, buffer_size) != FOTA_STATUS_SUCCESS) {
        DYNLOG_TRACE("fota_bd_read failed");
        _error_res->set_value(DYNLOG_ERROR_READ_FAILURE);
        goto cleanup;
    }

    _read_offset += buffer_size;

    // Update only when last response is sent
    if (last_block_response) {
        _unread_log_size->set_value(_write_offset - _read_offset);
    }

    buffer = _log_chunk;
    total_size = _total_log_size;

    return COAP_RESPONSE_CONTENT;

cleanup:

    free(_log_chunk);
    _log_chunk = NULL;
    buffer_size = 0;
    total_size = 0;

    return COAP_RESPONSE_NOT_ACCEPTABLE;
}

void M2MDynLog::erase_logs()
{
    // suspend capture while erasing logs
    mbed_trace_print_function_set(NULL);

    free_trace_list();

    _read_offset = _write_offset = fota_candidate_get_config()->storage_start_addr;
    fota_candidate_erase();

    // fota_candidate_erase removes the update storage file so it must be created again
#if defined(TARGET_LIKE_LINUX)
    (void) fota_bd_init();
#endif

    _unread_log_size->set_value(0);
    _total_log_size_res->set_value(0);

    mbed_trace_print_function_set(trace_output);
}

M2MDynLog::ErrorStatus M2MDynLog::store_trace_line(const char *line)
{
    size_t prog_size = FOTA_ALIGN_UP(strlen(line), _prog_size);
    if (_write_offset + prog_size >= _nvm_size->get_value_int() + fota_candidate_get_config()->storage_start_addr) {
        return DYNLOG_ERROR_STORAGE_FULL;
    }

    if (fota_bd_program(line, _write_offset, prog_size) != FOTA_STATUS_SUCCESS) {
        return DYNLOG_ERROR_WRITE_FAILURE;
    }

    _write_offset += prog_size;

    return DYNLOG_SUCCESS;
}

void M2MDynLog::free_trace_list()
{
    ns_list_foreach_safe(M2MDynLog::trace_list_s, tmp, &_trace_list) {
        free_trace_list_item(tmp);
    }
}

void M2MDynLog::free_trace_list_item(M2MDynLog::trace_list_s *item)
{
    ns_list_remove(&_trace_list, item);
    ns_mem_free(_mem_book, item->trace_line);
    ns_mem_free(_mem_book, item);
}

void M2MDynLog::store_to_ram(const char *str, M2MDynLog::trace_list_s *item)
{
    memcpy(item->trace_line, str, strlen(str));
    item->trace_line[strlen(str)] = '\n';
    item->trace_line[strlen(str) + 1] = '\0';
    ns_list_add_to_end(&_trace_list, item);
}

void M2MDynLog::kcm_set(const char *key, const uint8_t *buffer, size_t buffer_size)
{
    ccs_delete_item(key, CCS_CONFIG_ITEM);
    ccs_set_item(key, buffer, buffer_size, CCS_CONFIG_ITEM);
}

bool M2MDynLog::kcm_get(const char *key, uint8_t *buffer, size_t buffer_size, size_t *bytes_read) const
{
    return (ccs_get_item(key, buffer, buffer_size, bytes_read, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) ? true : false;
}

void M2MDynLog::read_defaults_from_kcm()
{
    uint8_t buf[4];
    size_t size = 0;
    if (kcm_get(logging_enabled_key, buf, 2, &size)) {
        _capture_ongoing = common_read_16_bit(buf);
    }

    if (kcm_get(read_offset_key, buf, 4, &size)) {
        _read_offset = common_read_32_bit(buf);
    } else {
        _read_offset = fota_candidate_get_config()->storage_start_addr;
    }

    if (kcm_get(write_offset_key, buf, 4, &size)) {
        _write_offset = common_read_32_bit(buf);
    } else {
        _write_offset = fota_candidate_get_config()->storage_start_addr;
    }

    DYNLOG_TRACE("read_defaults_from_kcm, enabled: %d, read offset: 0x%zx, write offset: 0x%zx", _capture_ongoing, _read_offset, _write_offset);
}

void M2MDynLog::store_trace_levels_to_kcm()
{
    uint8_t buf[2] = {0};
    common_write_16_bit(_trace_level_res->get_value_int(), buf);
    kcm_set(trace_level_key, buf, 2);
    common_write_16_bit(_trace_level_trigger_res->get_value_int(), buf);
    kcm_set(trace_level_trigger_key, buf, 2);
}

bool M2MDynLog::capture_active()
{
    return _capture_ongoing;
}

void M2MDynLog::store_success()
{
    _unread_log_size->set_value(_write_offset - _read_offset);
    uint8_t buf[4] = {0};
    common_write_32_bit(_write_offset, buf);
    kcm_set(write_offset_key, buf, 4);

    common_write_32_bit(_read_offset, buf);
    kcm_set(read_offset_key, buf, 4);

    _total_log_size_res->set_value(_write_offset - fota_candidate_get_config()->storage_start_addr);
}

void M2MDynLog::store_failed(M2MDynLog::ErrorStatus status)
{
    _error_res->set_value(status);
    if (status == M2MDynLog::DYNLOG_ERROR_STORAGE_FULL) {
        if (_erase_on_full_res->get_value_int()) {
            erase_logs();
            return;
        } else {
            // Waiting for user action to continue
            DYNLOG_TRACE("Storage full, stop");
        }
    }

    stop_capture(false, false);
}

void M2MDynLog::store(void *str)
{
    dynlog_mutex_wait();

    M2MDynLog::ErrorStatus status = DYNLOG_SUCCESS;

    mbed_trace_print_function_set(NULL);

    // Store items from buffer
    ns_list_foreach_safe(M2MDynLog::trace_list_s, temp, &_trace_list) {
        // If storing fails just remove remaining items from the list
        if (status == DYNLOG_SUCCESS) {
            status = store_trace_line(temp->trace_line);
        }

        free_trace_list_item(temp);
    }

    if (str && status == DYNLOG_SUCCESS) {
        status = store_trace_line((char *)str);
    }

    free(str);

    DYNLOG_TRACE("Write status: %d, current write_offset: 0x%zx, current read_offset: 0x%zx", status, _write_offset, _read_offset);

    if (status == DYNLOG_SUCCESS) {
        store_success();
        mbed_trace_print_function_set(trace_output);
    } else {
        store_failed(status);
    }

    dynlog_mutex_release();
}
// C wrappers
extern "C" void m2mdynlog_stop_capture(bool stopped_by_update)
{
    M2MDynLog::get_instance()->stop_capture(false, stopped_by_update);
}

extern "C" void m2mdynlog_start_log_capture()
{
    M2MDynLog::get_instance()->start_capture();
}

extern "C" bool m2mdynlog_is_capture_active()
{
    return M2MDynLog::get_instance()->capture_active();
}

#endif // MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE
