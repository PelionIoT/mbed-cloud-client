/*
 * Copyright (c) 2018 ARM Limited. All rights reserved.
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
#include "m2mnotificationhandler.h"
#include "eventOS_scheduler.h"
#include "m2mnsdlinterface.h"
#include "mbed-trace/mbed_trace.h"
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#define MBED_CLIENT_NOTIFICATION_HANDLER_TASKLET_INIT_EVENT 0 // Tasklet init occurs always when generating a tasklet
#define MBED_CLIENT_NOTIFICATION_HANDLER_EVENT 40
#define TRACE_GROUP "mClt"

int8_t M2MNotificationHandler::_tasklet_id = -1;

extern "C" void notification_tasklet_func(arm_event_s *event)
{
    M2MNsdlInterface *iface = (M2MNsdlInterface*)event->data_ptr;
    if (event->event_type == MBED_CLIENT_NOTIFICATION_HANDLER_EVENT) {
        iface->send_next_notification(false);
        event->event_data = 0;
    }
}

M2MNotificationHandler::M2MNotificationHandler()
{
    if (M2MNotificationHandler::_tasklet_id < 0) {
        M2MNotificationHandler::_tasklet_id = eventOS_event_handler_create(notification_tasklet_func, MBED_CLIENT_NOTIFICATION_HANDLER_TASKLET_INIT_EVENT);
        assert(M2MNotificationHandler::_tasklet_id >= 0);
    }

    initialize_event();
}

M2MNotificationHandler::~M2MNotificationHandler()
{
}

void M2MNotificationHandler::send_notification(M2MNsdlInterface *interface)
{
    tr_debug("M2MNotificationHandler::send_notification");
    if (!_event.data.event_data) {
        _event.data.event_data = 1;
        _event.data.event_type = MBED_CLIENT_NOTIFICATION_HANDLER_EVENT;
        _event.data.data_ptr = interface;

        eventOS_event_send_user_allocated(&_event);
    } else {
        tr_debug("M2MNotificationHandler::send_notification - event already in queue");
    }
}

void M2MNotificationHandler::initialize_event()
{
    _event.data.data_ptr = NULL;
    _event.data.event_data = 0;
    _event.data.event_id = 0;
    _event.data.sender = 0;
    _event.data.event_type = 0;
    _event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
    _event.data.receiver = M2MNotificationHandler::_tasklet_id;
}
