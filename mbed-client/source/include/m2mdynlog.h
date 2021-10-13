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

#ifndef M2MDYNLOG_H
#define M2MDYNLOG_H

#include "m2mconfig.h"

#if defined (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE) && (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE > 0)

#ifdef __cplusplus

#include "pal.h"
#include "m2minterface.h"
#include "nsdynmemLIB.h"
#include "ns_list.h"
#include "m2mresource.h"
#include "eventOS_event.h"

class M2MDynLog {

public:

    typedef struct trace_list_ {
        char                *trace_line;
        ns_list_link_t      link;
    } trace_list_s;

    typedef NS_LIST_HEAD(trace_list_s, link) trace_list_t;

    /**
     * \brief Get the singleton instance of M2MDynLog
     * \return Singleton instance.
     */
    static M2MDynLog *get_instance();

    /**
     * \brief Delete the singleton instance of M2MDynLog
     */
    static void delete_instance();

    /**
     *  \brief Event handler callback
     *
     *  \param event Event to process.
     */
    static void dynamic_log_tasklet(struct arm_event_s *event);

    /**
     * \brief Initializa M2MDynLog component.
     *
     * \param objects Resource list to be populated with new m2m objects
     * \param tasklet_id Event handler id
     */
    bool initialize(M2MBaseList &objects, const int8_t tasklet_id);

    /**
     * \brief Start log capture
     */
    void start_capture();

    /**
     * \brief Stop log capture
     *
     * \param stopped_by_user If stopped by user then buffer is flushed to NVM
     * \param stopped_by_update If true then error value "4" reported to Pelion.
     */
    void stop_capture(bool stopped_by_user, bool stopped_by_update);

    /**
     * \brief Is capture active
     *
     * \return True if active
     */
    bool capture_active();

    /**
     * \brief Store list items to NVM
     *
     * \param str Current trace line
     */
    void store_to_nvm(const char *str);

    /**
     * \brief Store trace line to linked list.
     *
     * \param str Current trace line
     * \param item Item to be stored into list
     */
    void store_to_ram(const char *str, M2MDynLog::trace_list_s *item);

    /**
     * \brief Handle mbed-trace output.
     *
     * \param str Trace line
     */
    void handle_trace_output(const char *str);

    /**
     * \brief Remove stored traces from NVM.
     */
    void erase_logs();

    /**
     * \brief Handle GET for resource 33456/0/3.
     *
     * \param[in]       resource        Pointer to resource whose value should will be read.
     * \param[out]      buffer          Pointer to value buffer.
     * \param[in, out]  buffer_size     On input, tells the maximum size of bytes to read. On output, tells how many bytes have been written to buffer.
     * \param[out]      total_size      Total size of the resource data.
     * \param[in]       offset          Offset to read from in data.
     * \param[in]       client_args     Client arguments.
     * \return CoAP response code for the response.
     */
    coap_response_code_e handle_read_request(const M2MResourceBase &resource, uint8_t *&buffer, size_t &buffer_size,
                                             size_t &total_size, const size_t offset, void *client_args);

    /**
     * \brief Store trace level and trace level trigger values to KCM.
     */
    void store_trace_levels_to_kcm();

private:

    /**
     * \brief An error code enum defining errors to be reported Pelion.
     */
    typedef enum {
        DYNLOG_SUCCESS = 0,
        DYNLOG_ERROR_STORAGE_FULL,
        DYNLOG_ERROR_READ_FAILURE,
        DYNLOG_ERROR_WRITE_FAILURE,
        DYNLOG_ERROR_ABORTED,
        DYNLOG_ERROR_OUT_OF_MEMORY
    } ErrorStatus;

    /**
     * \brief Constructor
     */
    M2MDynLog();

    // Prevents the use of assignment operator.
    M2MDynLog &operator=(const M2MDynLog & /*other*/);

    // Prevents the use of copy constructor
    M2MDynLog(const M2MDynLog & /*other*/);

    /**
     * \brief Destructor
     */
    virtual ~M2MDynLog();

    /**
     * \brief Creates m2m resources.
     *
     * \param objects Resource list to be populated with new m2m objects
     * \return True on success otherwise False.
     */
    bool create_resources(M2MBaseList &objects);

    /**
     * \brief Return current trace level.
     *
     * \param objects Resource list to be populated with new m2m objects
     * \return Active trace level output. CMD (0), ERROR (1), WARN (2), INFO (3), DEBUG(4)
     */
    int8_t get_trace_level() const;

    /**
     * \brief Return trace level set in compile time.
     *
     * \param objects Resource list to be populated with new m2m objects
     * \return Default trace level output. CMD (0), ERROR (1), WARN (2), INFO (3), DEBUG(4)
     */
    int8_t get_default_trace_level() const;

    /**
     * \brief Clears the whole trace list.
     */
    void free_trace_list();

    /**
     * \brief Remove trace item from list.
     *
     * \param item List item to be removed.
     */
    void free_trace_list_item(M2MDynLog::trace_list_s *item);

    /**
     * \brief Store single trace line into NVM.
     *
     * \param line Trace line to be stored.
     * \return DYNLOG_SUCCESS on success
     */
    ErrorStatus store_trace_line(const char *line);

    /**
     * \brief Read data from KCM.
     *
     * \param key KCM item name
     * \param buffer KCM item data output buffer
     * \param buffer_size Maximum size of the KCM item data output buffer.
     * \param bytes_read Actual KCM item data output buffer size in bytes.
     *
     * \return True on success
     */
    bool kcm_get(const char *key, uint8_t *buffer, size_t buffer_size, size_t *bytes_read) const;

    /**
     * \brief Store data to KCM.
     *
     * \param key KCM item name
     * \param buffer Data buffer to be stored to KCM
     * \param buffer_size Size of the data buffer
     */
    void kcm_set(const char *key, const uint8_t *buffer, size_t buffer_size);

    /**
     * \brief Load default values from KCM.
     */
    void read_defaults_from_kcm();

    /**
     * \brief Store operation success.
     */
    void store_success();

    /**
     * \brief Store operation failed.
     *
     * \param status Error code.
     */
    void store_failed(ErrorStatus status);

    /**
     * \brief Stop log capture
     *
     * \param stopped_by_user If stopped by user then buffer is flushed to NVM
     * \param stopped_by_update If true then error value "4" reported to Pelion.
     */
    void stop(bool stopped_by_user, bool stopped_by_update);

    /**
     * \brief Start log capture
     */
    void start();

    /**
     * \brief Clear logs from storage
     */
    void clear();

    /**
     * \brief Store logs
     * \param str Current trace line
     */
    void store(void *str);

    /**
     * \brief Initialize event
     * \param event Event to be initialized
     */
    void init_event(arm_event_storage_t *event);

#ifndef TARGET_LIKE_LINUX
    /**
     * \brief Erase whole update image storage area
     */
    bool erase_nvm();
#endif // !TARGET_LIKE_LINUX

    /**
     *  \brief Resource callbacks
     */
    static void trace_level_updated_cb(const char *object);
    static void start_logging_cb(void *args);
    static void stop_logging_cb(void *args);
    static void clear_logs_cb(void *args);
    static coap_response_code_e log_read_requested(const M2MResourceBase &resource,
                                                   uint8_t *&buffer,
                                                   size_t &buffer_size,
                                                   size_t &total_size,
                                                   const size_t offset,
                                                   void *client_args);

private:
    static M2MDynLog        *_instance;
    trace_list_t            _trace_list;
    bool                    _capture_ongoing;
    bool                    _keyword_found;
    bool                    _initialized;
    uint8_t                 _trace_buffer[MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE];
    int8_t                  _tasklet_id;
    char                    _trigger_string[6];
    arm_event_storage_t     _event;
    arm_event_storage_t     _store_event;
    size_t                  _total_log_size;
    size_t                  _write_offset;
    size_t                  _read_offset;
    size_t                  _prog_size;
    uint8_t                 *_log_chunk;
    ns_mem_book_t           *_mem_book;
    M2MResource             *_trace_level_res;          // 33456/0/5
    M2MResource             *_trace_level_trigger_res;  // 33456/0/6
    M2MResource             *_nvm_size;                 // 33456/0/7
    M2MResource             *_erase_on_full_res;        // 33456/0/8
    M2MResource             *_logging_enabled_res;      // 33456/0/9
    M2MResource             *_unread_log_size;          // 33456/0/10
    M2MResource             *_error_res;                // 33456/0/11
    M2MResource             *_total_log_size_res;       // 33456/0/12

    friend class Test_M2MDynLog;
};

#else // __cplusplus
void m2mdynlog_stop_capture(bool stopped_by_update);
void m2mdynlog_start_log_capture();
bool m2mdynlog_is_capture_active();
#endif

#endif // defined (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE) && (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE > 0)
#endif // M2MDYNLOG_H
