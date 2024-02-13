// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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

#include "fota_internal_ifs.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#include "fota/fota_event_handler.h"

void fota_internal_resume(fota_resume_reason_e resume_reason)
{
    fota_event_handler_defer_with_result_ignore_busy(fota_on_resume, resume_reason);
}

#endif
