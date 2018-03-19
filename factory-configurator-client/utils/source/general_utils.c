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

#include <stdbool.h>
#include <string.h>

bool is_memory_equal(const void *buf1, size_t size_of_buf1, const void *buf2, size_t size_of_buf2)
{
    return ((size_of_buf1 == size_of_buf2) && !memcmp(buf1, buf2, size_of_buf1));
}
