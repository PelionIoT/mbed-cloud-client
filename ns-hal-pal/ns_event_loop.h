// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef NS_EVENT_LOOP_H_
#define NS_EVENT_LOOP_H_

#ifdef __cplusplus
extern "C" {
#endif

void ns_event_loop_thread_create(void);
void ns_event_loop_thread_start(void);

// A extension to original event loop API, which is useful on Linux only
void ns_event_loop_thread_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* NS_EVENT_LOOP_H_ */
