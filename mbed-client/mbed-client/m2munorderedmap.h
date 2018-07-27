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

#ifndef M2M_UNORDERED_MAP_H
#define M2M_UNORDERED_MAP_H

/*! \file m2mpair.h
* \brief A simple C++ Map class, used as replacement for std::unordered_map.
* This map is implemented as a vector of Pair<Key, Value>. Searching is therefore O(N) and not O(1), 
* however for small-ish quantity of data this will be perfectly acceptable. 
* The main drawback of this implementation is that erasing objects is expensive and invalidates iterators.
*/

#include "m2mvector.h"
#include "m2mpair.h"

namespace m2m
{

    template <typename Key, typename Value>
    class UnorderedMap {
    public:
        typedef typename Vector<Pair<Key, Value> >::iterator iterator;
        typedef typename Vector<Pair<Key, Value> >::const_iterator const_iterator;

        Value& operator[](const Key& key) {
            // Find or insert default constructed value
            Pair<iterator, bool> p = insert(Pair<Key, Value>(key, Value()));
            return p.first->second;
        }

        iterator find( const Key& key ) {
            iterator it = _kv_pairs.begin();
            
            while(it != _kv_pairs.end())
            {
                if( it->first == key ) { 
                    // Found
                    break;
                }
                it++;
            }

            return it;
        }
	
        const_iterator find( const Key& key ) const {
            const_iterator it = _kv_pairs.begin();
            
            while(it != _kv_pairs.end())
            {
                if( it->first == key ) { 
                    // Found
                    break;
                }
                it++;
            }

            return it;
        }

        iterator begin() {
            return _kv_pairs.begin();
        }

        const_iterator begin() const {
            return _kv_pairs.begin();
        }

        iterator end() {
            return _kv_pairs.end();
        }

        const_iterator end() const {
            return _kv_pairs.end();
        }

        size_t count(const Key& key) const {
            if( find(key) != end() )
            {
                return 1;
            }
            else 
            {
                return 0;
            }
        }

        Pair<iterator, bool> insert(const Pair<Key, Value>& val) {
            iterator it = find(val.first);
            if( it != end() )
            {
                return Pair<iterator, bool>(it, false);
            }
            else 
            {
                _kv_pairs.push_back(val);
                it = _kv_pairs.end();
                it--;
                return Pair<iterator, bool>(it, true);
            }
        }

        // Note: This is the subset of methods required by MCC - obviously there's a bunch of methods missing

    private:
        Vector<Pair<Key, Value> > _kv_pairs;
    };

} // namespace

#endif // M2M_UNORDERED_MAP_H
