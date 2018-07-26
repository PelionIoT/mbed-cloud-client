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

#include "mbed-cloud-client/SimpleM2MResource.h"
#include "mbed-trace/mbed_trace.h"

#include <ctype.h>

#include<stdio.h>

#define TRACE_GROUP "mClt"


SimpleM2MResourceBase::SimpleM2MResourceBase()
: _client(NULL), _route("")
{
    tr_debug("SimpleM2MResourceBase::SimpleM2MResourceBase()");
}

SimpleM2MResourceBase::SimpleM2MResourceBase(MbedCloudClient* client, m2m::String route)
: _client(client),_route(route)
{
    tr_debug("SimpleM2MResourceBase::SimpleM2MResourceBase(), resource name %s\r\n", _route.c_str());
}

SimpleM2MResourceBase::~SimpleM2MResourceBase()
{
}

bool SimpleM2MResourceBase::define_resource_internal(m2m::String v, M2MBase::Operation opr, bool observable)
{
    tr_debug("SimpleM2MResourceBase::define_resource_internal(), resource name %s!\r\n", _route.c_str());

    m2m::Vector<m2m::String> segments = parse_route(_route.c_str());
    if (segments.size() != 3) {
        tr_debug("[SimpleM2MResourceBase] [ERROR] define_resource_internal(), Route needs to have three segments, split by '/' (%s)\r\n", _route.c_str());
        return false;
    }

    // segments[1] should be one digit and numeric
    if (!isdigit(segments.at(1).c_str()[0])) {
        tr_debug("[SimpleM2MResourceBase] [ERROR] define_resource_internal(), second route segment should be numeric, but was not (%s)\r\n", _route.c_str());
        return false;
    }

    int inst_id = atoi(segments.at(1).c_str());

    // Check if object exists
    M2MObject* obj;
    m2m::UnorderedMap<m2m::String,M2MObject*>::iterator obj_it = _client->_objects.find(segments[0]) ;
    if(obj_it != _client->_objects.end()) {
      tr_debug("Found object... %s\r\n", segments.at(0).c_str());
      obj = obj_it->second;
    } else {
        tr_debug("Create new object... %s\r\n", segments.at(0).c_str());
        obj = M2MInterfaceFactory::create_object(segments.at(0).c_str());
        if (!obj) {
            return false;
        }
        _client->_objects.insert(m2m::Pair<m2m::String, M2MObject*>(segments.at(0), obj));
    }

    // Check if object instance exists
    M2MObjectInstance* inst = obj->object_instance(inst_id);
    if(!inst) {
        tr_debug("Create new object instance... %s\r\n", segments.at(1).c_str());
        inst = obj->create_object_instance(inst_id);
        if(!inst) {
            return false;
        }
    }

    // @todo check if the resource exists yet
    M2MResource* res = inst->resource(segments.at(2).c_str());
    if(!res) {
        res = inst->create_dynamic_resource(segments.at(2).c_str(), "",
            M2MResourceInstance::STRING, observable);
        if(!res) {
            return false;
        }
        res->set_operation(opr);
        res->set_value((uint8_t*)v.c_str(), v.length());

        _client->_resources.insert(Pair<m2m::String, M2MResource*>(_route, res));
        _client->register_update_callback(_route, this);
    }

    return true;
}

m2m::Vector<m2m::String> SimpleM2MResourceBase::parse_route(const char* route)
{
    m2m::String s(route);
    m2m::Vector<m2m::String> v;
    size_t found = s.find_first_of("/");

    while (found!=m2m::String::npos) {
        v.push_back(s.substr(0,found));
        s = s.substr(found+1);
        found=s.find_first_of("/");
        if(found == m2m::String::npos) {
            v.push_back(s);
        }
    }
    return v;
}

m2m::String SimpleM2MResourceBase::get() const
{
    tr_debug("SimpleM2MResourceBase::get() resource (%s)", _route.c_str());
    if (!_client->_resources.count(_route)) {
        tr_debug("[SimpleM2MResourceBase] [ERROR] No such route (%s)\r\n", _route.c_str());
        return m2m::String();
    }

    // otherwise ask mbed Client...
    uint8_t* buffIn = NULL;
    uint32_t sizeIn;
    _client->_resources[_route]->get_value(buffIn, sizeIn);

    m2m::String s((char*)buffIn, sizeIn);
    tr_debug("SimpleM2MResourceBase::get() resource value (%s)", s.c_str());
    free(buffIn);
    return s;
}

bool SimpleM2MResourceBase::set(m2m::String v)
{
    // Potentially set() happens in InterruptContext. That's not good.
    tr_debug("SimpleM2MResourceBase::set() resource (%s)", _route.c_str());
    if (!_client->_resources.count(_route)) {
        tr_debug("[SimpleM2MResourceBase] [ERROR] No such route (%s)\r\n", _route.c_str());
        return false;
    }

    if (v.length() == 0) {
        _client->_resources[_route]->clear_value();
    }
    else {
        _client->_resources[_route]->set_value((uint8_t*)v.c_str(), v.length());
    }

    return true;
}

bool SimpleM2MResourceBase::set(const int& v)
{
    char buffer[20];
    int size = sprintf(buffer,"%d",v);
    m2m::String stringified(buffer,size);

    return set(stringified);
}

bool SimpleM2MResourceBase::set_post_function(void(*fn)(void*))
{
    //TODO: Check the resource exists with right operation being set or append the operation into it.
    M2MResource *resource = get_resource();
    if(!resource) {
        return false;
    }
    M2MBase::Operation op = resource->operation();
    op = (M2MBase::Operation)(op | M2MBase::POST_ALLOWED);
    resource->set_operation(op);

    _client->_resources[_route]->set_execute_function(execute_callback_2(fn));
    return true;
}

bool SimpleM2MResourceBase::set_post_function(execute_callback fn)
{
    //TODO: Check the resource exists with right operation being set or append the operation into it.
    M2MResource *resource = get_resource();
    if(!resource) {
        return false;
    }
    M2MBase::Operation op = resource->operation();
    op = (M2MBase::Operation)(op | M2MBase::POST_ALLOWED);
    resource->set_operation(op);

    // No clue why this is not working?! It works with class member, but not with static function...
    _client->_resources[_route]->set_execute_function(fn);
    return true;
}

M2MResource* SimpleM2MResourceBase::get_resource()
{
    if (!_client->_resources.count(_route)) {
        tr_debug("[SimpleM2MResourceBase] [ERROR] No such route (%s)\r\n", _route.c_str());
        return NULL;
    }
    return _client->_resources[_route];
}

SimpleM2MResourceString::SimpleM2MResourceString(MbedCloudClient* client,
                               const char* route,
                               m2m::String v,
                               M2MBase::Operation opr,
                               bool observable,
                               FP1<void, m2m::String> on_update)
: SimpleM2MResourceBase(client,route),_on_update(on_update)
{
    tr_debug("SimpleM2MResourceString::SimpleM2MResourceString() creating (%s)\r\n", route);
    define_resource_internal(v, opr, observable);
}

SimpleM2MResourceString::SimpleM2MResourceString(MbedCloudClient* client,
                               const char* route,
                               m2m::String v,
                               M2MBase::Operation opr,
                               bool observable,
                               void(*on_update)(m2m::String))

: SimpleM2MResourceBase(client,route)
{
    tr_debug("SimpleM2MResourceString::SimpleM2MResourceString() overloaded creating (%s)\r\n", route);
    FP1<void, m2m::String> fp;
    fp.attach(on_update);
    _on_update = fp;
    define_resource_internal(v, opr, observable);
}

SimpleM2MResourceString::~SimpleM2MResourceString()
{
}

m2m::String SimpleM2MResourceString::operator=(const m2m::String& new_value)
{
    tr_debug("SimpleM2MResourceString::operator=()");
    set(new_value);
    return new_value;
}

SimpleM2MResourceString::operator m2m::String() const
{
    tr_debug("SimpleM2MResourceString::operator m2m::String()");
    m2m::String value = get();
    return value;
}

void SimpleM2MResourceString::update()
{
    m2m::String v = get();
    _on_update(v);
}

SimpleM2MResourceInt::SimpleM2MResourceInt(MbedCloudClient* client,
                         const char* route,
                         int v,
                         M2MBase::Operation opr,
                         bool observable,
                         FP1<void, int> on_update)
: SimpleM2MResourceBase(client,route),_on_update(on_update)
{
    tr_debug("SimpleM2MResourceInt::SimpleM2MResourceInt() creating (%s)\r\n", route);
    char buffer[20];
    int size = sprintf(buffer,"%d",v);
    m2m::String stringified(buffer,size);
    define_resource_internal(stringified, opr, observable);
}

SimpleM2MResourceInt::SimpleM2MResourceInt(MbedCloudClient* client,
                         const char* route,
                         int v,
                         M2MBase::Operation opr,
                         bool observable,
                         void(*on_update)(int))
: SimpleM2MResourceBase(client,route)
{
    tr_debug("SimpleM2MResourceInt::SimpleM2MResourceInt() overloaded creating (%s)\r\n", route);
    FP1<void, int> fp;
    fp.attach(on_update);
    _on_update = fp;
    char buffer[20];
    int size = sprintf(buffer,"%d",v);
    m2m::String stringified(buffer,size);
    define_resource_internal(stringified, opr, observable);
}

SimpleM2MResourceInt::~SimpleM2MResourceInt()
{
}

int SimpleM2MResourceInt::operator=(int new_value)
{
    set(new_value);
    return new_value;
}

SimpleM2MResourceInt::operator int() const
{
    m2m::String v = get();
    if (v.empty()) return 0;

    return atoi((const char*)v.c_str());
}

void SimpleM2MResourceInt::update()
{
    m2m::String v = get();
    if (v.empty()) {
        _on_update(0);
    } else {
        _on_update(atoi((const char*)v.c_str()));
    }
}
