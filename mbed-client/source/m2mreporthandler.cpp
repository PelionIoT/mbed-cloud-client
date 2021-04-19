/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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
// Needed for PRIu64 on FreeRTOS
#include <stdio.h>
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "mbed-client/m2mreportobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mtimer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include <string.h>
#include <stdlib.h>

#define TRACE_GROUP "mClt"

M2MReportHandler::M2MReportHandler(M2MReportObserver &observer, M2MBase::DataType type)
    : _observer(observer),
      _is_under_observation(false),
      _observation_level(M2MBase::None),
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
      _attribute_state(0),
#endif
      _token_length(0),
      _resource_type(type),
      _notify(false),
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
      _pmin_exceeded(false),
      _pmax_exceeded(false),
#endif
      _observation_number(0),
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
      _pmin_timer(*this),
      _pmax_timer(*this),
#endif
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
      _pmax(-1.0f),
      _pmin(1.0f),
      _gt(0.0f),
      _lt(0.0f),
      _st(0.0f),
      _last_value_valid(false),
#endif
      _token(NULL),
      _notification_send_in_progress(false),
      _notification_in_queue(false),
      _blockwise_notify(false),
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
      _pmin_quiet_period(false),
#endif
      _waiting_to_report(false),
      _confirmable(true),
      _resource_base(NULL)
{
    tr_debug("M2MReportHandler::M2MReportHandler()");
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if (_resource_type == M2MBase::FLOAT) {
        _high_step.float_value = 0;
        _low_step.float_value = 0;
        _last_value.float_value = -1;
        _current_value.float_value = 0;
    } else {
        _high_step.int_value = 0;
        _low_step.int_value = 0;
        _last_value.int_value = -1;
        _current_value.int_value = 0;
    }
#endif
}

M2MReportHandler::~M2MReportHandler()
{
    tr_debug("M2MReportHandler::~M2MReportHandler()");
    free(_token);
}

void M2MReportHandler::set_under_observation(bool observed)
{
    tr_debug("M2MReportHandler::set_under_observation(observed %d)", (int)observed);

    _is_under_observation = observed;

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    stop_timers();
    if (observed) {
        handle_timers();
    } else {
        set_default_values();
    }
#else
    if (!observed) {
        set_default_values();
    }
#endif
}

void M2MReportHandler::set_value_float(float value)
{
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    tr_debug("M2MReportHandler::set_value_float() - current %f, last %f", value, _last_value.float_value);
    _current_value.float_value = value;

    if (!_last_value_valid || _current_value.float_value != _last_value.float_value) {
        send_value();
    }
#else
    send_value();
#endif
}

void M2MReportHandler::set_value_int(int64_t value)
{
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    tr_debug("M2MReportHandler::set_value_int() - current %" PRId64 ", last % " PRId64, value, _last_value.int_value);
    _current_value.int_value = value;

    if (!_last_value_valid || _current_value.int_value != _last_value.int_value) {
        send_value();
    }
#else
    send_value();
#endif
}

void M2MReportHandler::set_notification_trigger(uint16_t obj_instance_id)
{
    tr_debug("M2MReportHandler::set_notification_trigger(): %d", obj_instance_id);
    // Add to array if not there yet
    m2m::Vector<uint16_t>::const_iterator it;
    it = _changed_instance_ids.begin();
    bool found = false;
    for (; it != _changed_instance_ids.end(); it++) {
        if ((*it) == obj_instance_id) {
            found = true;
            break;
        }
    }
    if (!found) {
        _changed_instance_ids.push_back(obj_instance_id);
    }
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if (_resource_type == M2MBase::FLOAT) {
        _current_value.float_value = 0;
        _last_value.float_value = 1;
    } else {
        _current_value.int_value = 0;
        _last_value.int_value = 1;
    }
    _last_value_valid = false;
#endif
    if (_confirmable) {
        set_notification_in_queue(true);
    }
    schedule_report();
}

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
bool M2MReportHandler::parse_notification_attribute(const char *query,
                                                    M2MBase::BaseType type,
                                                    M2MResourceInstance::ResourceType resource_type)
{
    tr_debug("M2MReportHandler::parse_notification_attribute(Query %s, Base type %d)", query, (int)type);
    bool success = false;
    const char *sep_pos = strchr(query, '&');
    const char *rest = query;
    if (sep_pos != NULL) {
        char query_options[5][20];
        float pmin = _pmin;
        float pmax = _pmax;
        float lt = _lt;
        float gt = _gt;
        float st = _st;
        high_step_t high = _high_step;
        low_step_t low = _low_step;
        uint8_t attr = _attribute_state;

        memset(query_options, 0, sizeof(query_options[0][0]) * 5 * 20);
        uint8_t num_options = 0;
        while (sep_pos != NULL && num_options < 5) {
            size_t len = (size_t)(sep_pos - rest);
            if (len > 19) {
                len = 19;
            }
            memcpy(query_options[num_options], rest, len);
            sep_pos++;
            rest = sep_pos;
            sep_pos = strchr(rest, '&');
            num_options++;
        }
        if (num_options < 5 && strlen(rest) > 0) {
            size_t len = (size_t)strlen(rest);
            if (len > 19) {
                len = 19;
            }
            memcpy(query_options[num_options++], rest, len);
        }

        for (int option = 0; option < num_options; option++) {
            success = set_notification_attribute(query_options[option], type, resource_type);
            if (!success) {
                tr_error("M2MReportHandler::parse_notification_attribute - break");
                break;
            }
        }

        if (success) {
            success = check_attribute_validity();
        } else {
            tr_debug("M2MReportHandler::parse_notification_attribute - not valid query");
            _pmin = pmin;
            _pmax = pmax;
            _st = st;
            _lt = lt;
            _gt = gt;
            _high_step = high;
            _low_step = low;
            _attribute_state = attr;
        }
    } else {
        if (set_notification_attribute(query, type, resource_type)) {
            success = check_attribute_validity();
        }
    }

    return success;
}

void M2MReportHandler::timer_expired(M2MTimerObserver::Type type)
{
    switch (type) {
        case M2MTimerObserver::PMinTimer: {
            tr_debug("M2MReportHandler::timer_expired - PMIN");

            _pmin_exceeded = true;
            if (_notify || _waiting_to_report ||
                    (_pmin > 0 && (_attribute_state & M2MReportHandler::Pmax) != M2MReportHandler::Pmax)) {
                report();
            }

            // If value hasn't changed since last expiration, next value change should send notification immediately
            if (_resource_type == M2MBase::FLOAT) {
                if (_current_value.float_value == _last_value.float_value) {
                    _pmin_quiet_period = true;
                }
            } else {
                if (_current_value.int_value == _last_value.int_value) {
                    _pmin_quiet_period = true;
                }
            }
        }
        break;
        case M2MTimerObserver::PMaxTimer: {
            tr_debug("M2MReportHandler::timer_expired - PMAX");
            _pmax_exceeded = true;
            if (_pmin_exceeded ||
                    (_attribute_state & M2MReportHandler::Pmin) != M2MReportHandler::Pmin) {
                report();
            }
        }
        break;
        default:
            break;
    }
}

bool M2MReportHandler::set_notification_attribute(const char *option,
                                                  M2MBase::BaseType type,
                                                  M2MResourceInstance::ResourceType resource_type)
{
    bool success = false;
    const int max_size = 20;
    char attribute[max_size];
    char value[max_size];

    const char *pos = strstr(option, EQUAL);
    if (pos) {
        size_t attr_len = pos - option;
        // Skip the "=" mark
        pos++;
        size_t value_len = strlen(pos);
        if (value_len && value_len < max_size && attr_len < max_size) {
            memcpy(attribute, option, attr_len);
            attribute[attr_len] = '\0';
            memcpy(value, pos, value_len);
            value[value_len] = '\0';
            success = true;
        }
    }

    if (success) {
        if (strcmp(attribute, PMIN) == 0) {
            _pmin = atoi(value);
            success = true;
            _attribute_state |= M2MReportHandler::Pmin;
            tr_info("observation_attributes %s %" PRId32, attribute, _pmin);
        } else if (strcmp(attribute, PMAX) == 0) {
            _pmax = atoi(value);
            success = true;
            _attribute_state |= M2MReportHandler::Pmax;
            tr_info("observation_attributes %s %" PRId32, attribute, _pmax);
        } else if (strcmp(attribute, GT) == 0 &&
                   (M2MBase::Resource == type)) {
            success = true;
            _gt = atof(value);
            _attribute_state |= M2MReportHandler::Gt;
            tr_info("observation_attributes %s %f", attribute, _gt);
        } else if (strcmp(attribute, LT) == 0 &&
                   (M2MBase::Resource == type)) {
            success = true;
            _lt = atof(value);
            _attribute_state |= M2MReportHandler::Lt;
            tr_info("observation_attributes %s %f", attribute, _lt);
        } else if ((strcmp(attribute, ST_SIZE) == 0)
                   && (M2MBase::Resource == type)) {
            success = true;
            _st = atof(value);
            if (_resource_type == M2MBase::FLOAT) {
                _high_step.float_value = _current_value.float_value + _st;
                _low_step.float_value = _current_value.float_value - _st;
            } else {
                _high_step.int_value = _current_value.int_value + _st;
                _low_step.int_value = _current_value.int_value - _st;
            }

            _attribute_state |= M2MReportHandler::St;
            tr_info("observation_attributes %s %f", attribute, _st);
        } else {
            tr_error("M2MReportHandler::set_notification_attribute - unknown write attribute!");
            success = false;
        }

        // Return false if try to set gt,lt or st when the resource type is something else than numerical
        if (success &&
                (resource_type != M2MResourceInstance::INTEGER && resource_type != M2MResourceInstance::FLOAT) &&
                ((_attribute_state & M2MReportHandler::Gt) == M2MReportHandler::Gt ||
                 (_attribute_state & M2MReportHandler::Lt) == M2MReportHandler::Lt ||
                 (_attribute_state & M2MReportHandler::St) == M2MReportHandler::St)) {
            tr_debug("M2MReportHandler::set_notification_attribute - not numerical resource");
            success = false;
        }
    } else {
        tr_error("M2MReportHandler::set_notification_attribute - failed to parse query!");
    }
    return success;
}
#endif

void M2MReportHandler::schedule_report(bool in_queue)
{
    tr_debug("M2MReportHandler::schedule_report()");
    _notify = true;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if ((_attribute_state & M2MReportHandler::Pmin) != M2MReportHandler::Pmin ||
            _pmin_exceeded ||
            _pmin_quiet_period) {
        report(in_queue);
    }
#else
    report(in_queue);
#endif

}

void M2MReportHandler::report(bool in_queue)
{
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if (_resource_type == M2MBase::FLOAT) {
        tr_debug("M2MReportHandler::report() - current %2f, last %2f, notify %d, queued %d", _current_value.float_value, _last_value.float_value, _notify, in_queue);
    } else {
        tr_debug("M2MReportHandler::report() - current %" PRId64 ", last % " PRId64 ", notify %d, queued %d", _current_value.int_value, _last_value.int_value, _notify, in_queue);
    }

    bool value_changed = false;

    if (_resource_type == M2MBase::FLOAT) {
        if (_current_value.float_value != _last_value.float_value) {
            value_changed = true;
        }
    } else {
        if (_current_value.int_value != _last_value.int_value) {
            value_changed = true;
        }
    }
#else
    bool value_changed = true;
#endif

    if ((value_changed && _notify) || in_queue) {
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
        if (_pmin_exceeded) {
            tr_debug("M2MReportHandler::report()- send with PMIN expiration");
        } else {
            tr_debug("M2MReportHandler::report()- send with VALUE change");
        }

        _pmin_exceeded = false;
        _pmax_exceeded = false;
        _pmin_quiet_period = false;
#endif
        _notify = false;
        _observation_number++;

        if (_observation_number == 1) {
            // Increment the observation number by 1 if it is already 1 because CoAP specification has reserved 1 for DEREGISTER notification
            _observation_number++;
        }

        if (_observer.observation_to_be_sent(_changed_instance_ids, observation_number())) {
            _changed_instance_ids.clear();
            if (_confirmable) {
                set_notification_send_in_progress(true);
            }
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
            if (_resource_type == M2MBase::FLOAT) {
                _last_value.float_value = _current_value.float_value;
            } else {
                _last_value.int_value = _current_value.int_value;
            }
            _last_value_valid = true;
#endif
        }
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
        _pmax_timer.stop_timer();
#endif
    }
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    else {
        if (_pmax_exceeded) {
            tr_debug("M2MReportHandler::report()- send with PMAX expiration");
            _observation_number++;

            if (_observation_number == 1) {
                // Increment the observation number by 1 if it is already 1 because CoAP specification has reserved 1 for DEREGISTER notification
                _observation_number++;
            }

            if (_observer.observation_to_be_sent(_changed_instance_ids, observation_number(), true)) {
                _changed_instance_ids.clear();
                if (_confirmable) {
                    set_notification_send_in_progress(true);
                }
            } else {
                if (_confirmable) {
                    set_notification_in_queue(true);
                }
            }
            if (_resource_type == M2MBase::FLOAT) {
                _last_value.float_value = _current_value.float_value;
            } else {
                _last_value.int_value = _current_value.int_value;
            }
            _last_value_valid = true;
        } else {
            tr_debug("M2MReportHandler::report()- no need to send");
        }
    }
    if (_waiting_to_report) {
        tr_debug("M2MReportHandler::report()- reporting to resource parents");
        _resource_base->report_to_parents();
        _waiting_to_report = false;
    }
    handle_timers();
#endif
}

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
void M2MReportHandler::start_timers()
{
    tr_debug("M2MReportHandler::start_timers");
    handle_timers();
}

void M2MReportHandler::handle_timers()
{
    tr_debug("M2MReportHandler::handle_timers()");
    uint64_t time_interval = 0;
    if ((_attribute_state & M2MReportHandler::Pmin) == M2MReportHandler::Pmin) {
        if (_pmin == _pmax) {
            _pmin_exceeded = true;
        } else {
            _pmin_exceeded = false;
            time_interval = (uint64_t)((uint64_t)_pmin * 1000);
            tr_debug("M2MReportHandler::handle_timers() - Start PMIN interval: %d", (int)time_interval);
            _pmin_timer.start_timer(time_interval,
                                    M2MTimerObserver::PMinTimer,
                                    true);
        }
    }
    if ((_attribute_state & M2MReportHandler::Pmax) == M2MReportHandler::Pmax) {
        if (_pmax > 0) {
            time_interval = (uint64_t)((uint64_t)_pmax * 1000);
            tr_debug("M2MReportHandler::handle_timers() - Start PMAX interval: %d", (int)time_interval);
            _pmax_timer.start_timer(time_interval,
                                    M2MTimerObserver::PMaxTimer,
                                    true);
        }
    }
}

bool M2MReportHandler::check_attribute_validity() const
{
    bool success = true;
    if ((_attribute_state & M2MReportHandler::Pmax) == M2MReportHandler::Pmax &&
            ((_pmax >= -1.0) && (_pmin > _pmax))) {
        success = false;
    }
    float low = _lt + 2 * _st;
    if ((_attribute_state & M2MReportHandler::Gt) == M2MReportHandler::Gt &&
            (low >= _gt)) {
        success = false;
    }
    return success;
}

void M2MReportHandler::stop_timers()
{
    tr_debug("M2MReportHandler::stop_timers()");

    _pmin_exceeded = false;
    _pmin_timer.stop_timer();

    _pmax_exceeded = false;
    _pmax_timer.stop_timer();

    tr_debug("M2MReportHandler::stop_timers() - out");
}
#endif

void M2MReportHandler::set_default_values()
{
    tr_debug("M2MReportHandler::set_default_values");
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    _pmax = -1.0;
    _pmin = 1.0;
    _gt = 0.0f;
    _lt = 0.0f;
    _st = 0.0f;
    _pmin_exceeded = false;
    _pmax_exceeded = false;
    _attribute_state = 0;
#endif
    _changed_instance_ids.clear();
    _notification_in_queue = false;
    _notification_send_in_progress = false;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    _pmin_quiet_period = false;
    if (_resource_type == M2MBase::FLOAT) {
        _high_step.float_value = 0.0f;
        _low_step.float_value = 0.0f;
        _last_value.float_value = -1.0f;
    } else {
        _high_step.int_value = 0;
        _low_step.int_value = 0;
        _last_value.int_value = -1;
    }
    _last_value_valid = false;
#endif
}

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
void M2MReportHandler::init_float_values(float value)
{
    _current_value.float_value = value;
    _last_value.float_value = value;
    _last_value_valid = false;
}

void M2MReportHandler::init_int_values(int64_t value)
{
    _current_value.int_value = value;
    _last_value.int_value = value;
    _last_value_valid = false;
}

bool M2MReportHandler::check_threshold_values() const
{
    tr_debug("M2MReportHandler::check_threshold_values");
    if (_resource_type == M2MBase::FLOAT) {
        tr_debug("Current value: %f", _current_value.float_value);
        tr_debug("Last value: %f", _last_value.float_value);
        tr_debug("High step: %f", _high_step.float_value);
        tr_debug("Low step: %f", _low_step.float_value);
    } else {
        tr_debug("Current value: %" PRId64, _current_value.int_value);
        tr_debug("Last value: %" PRId64, _last_value.int_value);
        tr_debug("High step: %" PRId64, _high_step.int_value);
        tr_debug("Low step: %" PRId64, _low_step.int_value);
    }

    tr_debug("Less than: %f", _lt);
    tr_debug("Greater than: %f", _gt);
    tr_debug("Step: %f", _st);

    bool can_send = check_gt_lt_params();
    if (can_send) {
        if ((_attribute_state & M2MReportHandler::St) == M2MReportHandler::St) {
            can_send = false;

            if (_resource_type == M2MBase::FLOAT) {
                if (_current_value.float_value >= _high_step.float_value ||
                        _current_value.float_value <= _low_step.float_value) {
                    can_send = true;
                }
            } else {
                if ((_current_value.int_value >= _high_step.int_value ||
                        _current_value.int_value <= _low_step.int_value)) {
                    can_send = true;
                }
            }
        }
    }

    tr_debug("M2MReportHandler::check_threshold_values - value can be sent = %d", (int)can_send);
    return can_send;
}

bool M2MReportHandler::check_gt_lt_params() const
{
    tr_debug("M2MReportHandler::check_gt_lt_params");
    if (!_last_value_valid) {
        tr_debug("No valid _last_value, sending initial notification");
        return true;
    }
    bool can_send = false;
    // GT & LT set.
    if ((_attribute_state & (M2MReportHandler::Lt | M2MReportHandler::Gt)) ==
            (M2MReportHandler::Lt | M2MReportHandler::Gt)) {
        if (_resource_type == M2MBase::FLOAT) {
            if ((_current_value.float_value > _gt  && _last_value.float_value <= _gt) ||
                    (_current_value.float_value < _lt && _last_value.float_value >= _lt)) {
                can_send = true;
            } else if ((_current_value.float_value <= _gt && _last_value.float_value > _gt) ||
                       (_current_value.float_value >= _lt && _last_value.float_value < _lt)) {
                can_send = true;
            }
        } else {
            if ((_current_value.int_value > _gt && _last_value.int_value <= _gt) ||
                    (_current_value.int_value < _lt && _last_value.int_value >= _lt)) {
                can_send = true;
            } else if ((_current_value.int_value <= _gt && _last_value.int_value > _gt) ||
                       (_current_value.int_value >= _lt && _last_value.int_value < _lt)) {
                can_send = true;
            }
        }
    }
    // Only LT
    else if ((_attribute_state & M2MReportHandler::Lt) == M2MReportHandler::Lt &&
             (_attribute_state & M2MReportHandler::Gt) == 0) {
        if (_resource_type == M2MBase::FLOAT) {
            if (_current_value.float_value < _lt && _last_value.float_value >= _lt) {
                can_send = true;
            } else if (_current_value.float_value >= _lt && _last_value.float_value < _lt) {
                can_send = true;
            }
        } else {
            if (_current_value.int_value < _lt && _last_value.int_value >= _lt) {
                can_send = true;
            } else if (_current_value.int_value >= _lt && _last_value.int_value < _lt) {
                can_send = true;
            }
        }

    }
    // Only GT
    else if ((_attribute_state & M2MReportHandler::Gt) == M2MReportHandler::Gt &&
             (_attribute_state & M2MReportHandler::Lt) == 0) {
        if (_resource_type == M2MBase::FLOAT) {
            if (_current_value.float_value > _gt && _last_value.float_value <= _gt) {
                can_send = true;
            } else if (_current_value.float_value <= _gt && _last_value.float_value > _gt) {
                can_send = true;
            }
        } else {
            if (_current_value.int_value > _gt && _last_value.int_value <= _gt) {
                can_send = true;
            } else if (_current_value.int_value <= _gt && _last_value.int_value > _gt) {
                can_send = true;
            }
        }

    }
    // GT & LT not set.
    else {
        can_send = true;
    }
    tr_debug("M2MReportHandler::check_gt_lt_params - value in range = %d", (int)can_send);
    return can_send;
}

uint8_t M2MReportHandler::attribute_flags() const
{
    return _attribute_state;
}
#endif

void M2MReportHandler::set_observation_token(const uint8_t *token, const uint8_t length)
{
    free(_token);
    _token = NULL;
    _token_length = 0;

    if (token != NULL && length > 0) {
        _token = alloc_copy((uint8_t *)token, length);
        if (_token) {
            _token_length = length;
        }
    }
}

void M2MReportHandler::get_observation_token(uint8_t *token, uint8_t &token_length) const
{
    memcpy(token, _token, _token_length);
    token_length = _token_length;
}

uint16_t M2MReportHandler::observation_number() const
{
    return _observation_number;
}

void M2MReportHandler::add_observation_level(M2MBase::Observation obs_level)
{
    _observation_level = (M2MBase::Observation)(_observation_level | obs_level);
}

void M2MReportHandler::remove_observation_level(M2MBase::Observation obs_level)
{
    _observation_level = (M2MBase::Observation)(_observation_level & ~obs_level);
}

M2MBase::Observation M2MReportHandler::observation_level() const
{
    return _observation_level;
}

bool M2MReportHandler::is_under_observation() const
{
    return _is_under_observation;
}

void M2MReportHandler::wait_to_report(M2MResourceBase *resource_base)
{
    assert(resource_base != NULL);

    _waiting_to_report = true;
    _resource_base = resource_base;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    //Report immediately if the pmin timer has been exceeded or pmin is not set
    if (((_attribute_state & M2MReportHandler::Pmin) == M2MReportHandler::Pmin &&
            _pmin_exceeded) ||
            ((_attribute_state & M2MReportHandler::Pmin) != M2MReportHandler::Pmin)) {
        report();
    }
#else
    report();
#endif
}

uint8_t *M2MReportHandler::alloc_copy(const uint8_t *source, uint32_t size)
{
    assert(source != NULL);

    uint8_t *result = (uint8_t *)malloc(size);
    if (result) {
        memcpy(result, source, size);
    }
    return result;
}

void M2MReportHandler::set_notification_in_queue(bool to_queue)
{
    _notification_in_queue = to_queue;
}

bool M2MReportHandler::notification_in_queue() const
{
    return _notification_in_queue;
}

void M2MReportHandler::set_notification_send_in_progress(bool progress)
{
    _notification_send_in_progress = progress;
}

bool M2MReportHandler::notification_send_in_progress() const
{
    return _notification_send_in_progress;
}

void M2MReportHandler::set_blockwise_notify(bool blockwise_notify)
{
    _blockwise_notify = blockwise_notify;
}

bool M2MReportHandler::blockwise_notify() const
{
    return _blockwise_notify;
}

void M2MReportHandler::send_value()
{
    tr_debug("M2MReportHandler::send_value() - new value");
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if (check_threshold_values()) {
        if (_confirmable) {
            set_notification_in_queue(true);
        }
        if (_resource_type == M2MBase::FLOAT) {
            _high_step.float_value = _current_value.float_value + _st;
            _low_step.float_value = _current_value.float_value - _st;
        }
        if (_resource_type == M2MBase::INTEGER) {
            _high_step.int_value = _current_value.int_value + _st;
            _low_step.int_value = _current_value.int_value - _st;
        }
        schedule_report();
    } else {
        tr_debug("M2MReportHandler::send_value - value not in range");
        _notify = false;
        if ((_attribute_state & M2MReportHandler::Lt) == M2MReportHandler::Lt ||
                (_attribute_state & M2MReportHandler::Gt) == M2MReportHandler::Gt ||
                (_attribute_state & M2MReportHandler::St) == M2MReportHandler::St) {
            tr_debug("M2MReportHandler::send_value - stop pmin timer");
            _pmin_timer.stop_timer();
            _pmin_exceeded = true;
        }
    }
#else
    if (_confirmable) {
        set_notification_in_queue(true);
    }
    schedule_report();
#endif
}

void M2MReportHandler::set_confirmable(bool confirmable)
{
    _confirmable = confirmable;
}

bool M2MReportHandler::is_confirmable() const
{
    return _confirmable;
}
