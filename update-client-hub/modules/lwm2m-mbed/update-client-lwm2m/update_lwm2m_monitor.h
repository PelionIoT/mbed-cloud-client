// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef __UPDATE_LWM2M_MONITOR_H__
#define __UPDATE_LWM2M_MONITOR_H__

#include "lwm2m-source.h"

#ifdef LWM2M_SOURCE_USE_C_API

#include "update-client-monitor/arm_uc_monitor.h"

const ARM_UPDATE_MONITOR *get_update_lwm2m_monitor(void);

#endif //LWM2M_SOURCE_USE_C_API

#endif //__UPDATE_LWM2M_MONITOR_H__

