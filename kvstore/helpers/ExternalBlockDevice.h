/* mbed Microcontroller Library
 * Copyright (c) 2020 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EXTERNAL_BLOCK_DEVICE_H
#define EXTERNAL_BLOCK_DEVICE_H

#include "BlockDevice.h"

namespace mbed {

    class ExternalBlockDevice : public BlockDevice {
    public:
        ExternalBlockDevice();
        virtual ~ExternalBlockDevice();
        virtual int init();
        virtual int deinit();
        virtual int read(void *buffer, bd_addr_t addr, bd_size_t size);
        virtual int program(const void *buffer, bd_addr_t addr, bd_size_t size);
        virtual int erase(bd_addr_t addr, bd_size_t size);
        virtual bd_size_t get_read_size() const;
        virtual bd_size_t get_program_size() const;
        virtual bd_size_t get_erase_size() const;
        virtual bd_size_t size() const;
        virtual const char *get_type() const;
        virtual int get_erase_value() const;
    };

} // namespace mbed

#endif
