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

#ifndef M2MNOTIFICATIONHANDLER_H
#define M2MNOTIFICATIONHANDLER_H

#include "ns_types.h"
#include "eventOS_event.h"

class M2MNsdlInterface;
class M2MNotificationHandler {

public:
    M2MNotificationHandler();

    ~M2MNotificationHandler();

    void send_notification(M2MNsdlInterface *interface);

private:
    void initialize_event();

private:
    static int8_t       _tasklet_id;
    arm_event_storage_t _event;
};

#endif // M2MNOTIFICATIONHANDLER_H
