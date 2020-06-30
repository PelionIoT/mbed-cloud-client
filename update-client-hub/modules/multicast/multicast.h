// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef ARM_UC_MULTICAST_H
#define ARM_UC_MULTICAST_H

#define ARM_UC_OTA_MULTICAST_UC_HUB_EVENT   1
#define ARM_UC_OTA_MULTICAST_TIMER_EVENT    2
#define ARM_UC_OTA_MULTICAST_DL_DONE_EVENT  3

#ifdef __cplusplus
#include "m2minterface.h"
#include "ConnectorClient.h"

int arm_uc_multicast_init(M2MBaseList& list, ConnectorClient &client);

void arm_uc_multicast_deinit();

bool arm_uc_multicast_interface_configure(int8_t interface_id);
#endif

#endif /* ARM_UC_MULTICAST_H */
