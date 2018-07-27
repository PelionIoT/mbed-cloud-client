/*
 * Copyright (c) 2015-2018 ARM Limited. All rights reserved.
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

#ifndef M2M_PAIR_H
#define M2M_PAIR_H

/*! \file m2mpair.h
* \brief A simple C++ Pair class, used as replacement for std::pair.
*/

namespace m2m
{
    template <typename T1, typename T2>
    struct Pair {
        Pair() {} 
        Pair(const Pair& p) : first(p.first), second(p.second) {} 
        Pair(const T1& first, const T2& second) : first(first), second(second) {
        }
        template <class T3, class T4> Pair& operator=(const Pair<T3, T4>& p) {
            first = p.first;
            second = p.second;
            return *this;
        }

        T1 first;
        T2 second;
    };

} // namespace

#endif // M2M_PAIR_H
