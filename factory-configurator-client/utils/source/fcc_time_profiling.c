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


#include "fcc_time_profiling.h"

#ifdef FCC_TIME_PROFILING

uint64_t fcc_gen_timer = 0;
uint64_t fcc_bundle_timer = 0;
uint64_t fcc_key_timer = 0;
uint64_t fcc_certificate_timer = 0;
uint64_t fcc_config_param_timer = 0;
uint64_t fcc_certificate_chain_timer = 0;
#endif

