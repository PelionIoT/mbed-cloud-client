/*
 * Copyright (c) 2015-2020 ARM Limited. All rights reserved.
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
#include "mbed-client/m2mstring.h"
#include <string.h> // strlen
#include <stdlib.h> // malloc, realloc
#include <assert.h>

namespace m2m {


// can't use std::min as it is not universally available
#ifndef MIN
#define MIN(A,B) ((A) < (B) ? (A) : (B))
#endif

// (space needed for -3.402823 × 10^38) + (magic decimal 6 digits added as no precision is added to "%f") + trailing zero
#define REGISTRY_FLOAT_STRING_MAX_LEN 48

const String::size_type String::npos = static_cast<size_t>(-1);

char* String::strdup(const char* s)
{
    const size_t len = strlen(s)+1;
    char *p2 = static_cast<char*>(malloc(len));
    if (p2) {
        memcpy(p2, s, len);
        allocated_ = len;
        size_ = len-1;
    }
    return p2;
}

String::String()
    : p( strdup("") )
{
}

String::~String()
{
    free(p);
    p = 0;
}

String::String(const String& s)
    : p(0)
{
    p = static_cast<char*>(malloc(s.size_ + 1));

    allocated_ = s.size_ + 1;
    size_      = s.size_;
    memcpy(p, s.p, size_ + 1);
}

String::String(const char* s)
    : p(strdup(s))
{
}

String::String(const char* str, size_t n)
{
    p = static_cast<char*>(malloc(n + 1));

    allocated_ = n + 1;
    size_      = n;
    memcpy(p, str, n);
    p[n] = 0;
}

String& String::operator=(const char* s)
{
    if ( p != s ) {
        // s could point into our own string, so we have to allocate a new string
        const size_t len = strlen(s);
        char* copy = (char*) malloc( len + 1);
        memmove(copy, s, len+1); // trailing 0
        free( p );
        p = copy;
        size_ = len;
        allocated_ = len+1;
    }
    return *this;
}

String& String::operator=(const String& s)
{
    return operator=(s.p);
}

String& String::operator+=(const String& s)
{
    if (s.size_ > 0) {
        this->reserve(size_ + s.size_);
        memmove(p+size_, s.p, s.size_+1); // trailing 0
        size_ += s.size_;
    }
    return *this;
}

// since p and s may overlap, we have to copy our own string first
String& String::operator+=(const char* s)
{
    const size_type lens = strlen(s);
    if (lens > 0) {
        if (size_ + lens + 1 <= allocated_) {
            memmove(p+size_, s, lens+1); // trailing 0
            size_ += lens;
        } else {
            String s2( *this );  // copy own data
            s2.reserve(size_ + lens);
            memmove(s2.p+size_, s, lens+1); // trailing 0
            s2.size_ = size_ + lens;
            this->swap( s2 );
        }
    }
    return *this;
}

String& String::operator+=(const char c)
{
    push_back(c);
    return *this;
}

void String::push_back(const char c) {

    if (size_ == allocated_ - 1) {
        size_t more =  (allocated_* 3) / 2; // factor 1.5
        if ( more < 4 ) more = 4;
        reserve( size_ + more );
    }

    p[size_] = c;
    size_++;
    p[size_] = 0;
}

bool String::operator==(const char* s) const
{
    if( s == NULL ) {
        if( p == NULL ) {
            return true;
        }
        return false;
    }
    bool ret = strcmp(p, s);
    return !ret;
}

bool String::operator==(const String& s) const
{
    bool ret = strcmp(p, s.p);
    return !ret;
}

void String::clear()
{
    size_ = 0;
    p[0]  = 0;
}

String String::substr(const size_type pos, size_type length) const
{
    String s;
    const size_type len = size_;

    if ( pos <= len ) {

        size_type remain = len - pos;

        if ( length > remain )
            length = remain;

        s.reserve( length );

        memcpy(s.p, p + pos, length);
        s.p[length] = '\0';
        s.size_ = length;
    }
    return s;
}


// checked access, accessing the NUL at end is allowed
char String::at(const size_type i) const
{
    if ( i <= strlen(p) ) {
        return p[i];
    } else {
        return '\0';
    }
}

String& String::erase(size_type pos, size_type len)
{
    if (len > 0) {

        if ( pos < size_ ) { // user must not remove trailing 0

            size_type s2 = size_;
            size_type remain = s2 - pos - len;

            if (remain > 0) {
                // erase by overwriting
                memmove(p + pos, p + pos + len, remain);
            }

            //if ( remain < 0 ) remain = 0;

            // remove unused space
            this->resize( pos+remain );

        }
    }
    return *this;
}

String& String::append( const char* str, size_type n) {
    if (str && n > 0) {
        size_t lens = strlen(str);
        if (n > lens)
            n = lens;
        size_t newlen = size_ + n;
        this->reserve( newlen );
        memmove(p+size_, str, n); // p and s.p MAY overlap
        p[newlen] = 0; // add NUL termination
        size_ = newlen;
    }
    return *this;
}

String& String::append_raw( const char* str, size_type n) {
    if (str && n > 0) {
        size_t newlen = size_ + n;
        this->reserve( newlen );
        memmove(p+size_, str, n); // p and s.p MAY overlap
        p[newlen] = 0; // add NUL termination
        size_ = newlen;
    }
    return *this;
}

void String::append_int(int param) {

    // max len of "-9223372036854775808" plus zero termination
    char conv_buff[20+1];

    int len = itoa_c(param, conv_buff);
    append_raw(conv_buff, len);
}

int String::compare( size_type pos, size_type len, const String& str ) const {
    int r = -1;
    if (pos <= size_) {
        if ( len > size_ - pos)
            len = size_ - pos; // limit len to available length

        const size_type osize = str.size();
        const size_type len2   = MIN(len, osize);
        r = strncmp( p + pos, str.p, len2);
        if (r==0) // equal so far, now compare sizes
            r = len < osize ? -1 : ( len == osize ? 0 : +1 );
    }
    return r;
}

int String::compare( size_type pos, size_type len, const char* str ) const {
    int r = -1;
    if (pos <= size_) {

        if ( len > size_ - pos)
            len = size_ - pos; // limit len to available length

        const size_type osize = strlen(str);
        const size_type len2   = MIN(len, osize);
        r = strncmp( p + pos, str, len2);
        if (r==0) // equal so far, now compare sizes
            r = len < osize ? -1 : ( len == osize ? 0 : +1 );
    }
    return r;
}

int String::find_last_of(char c) const {
    int r = -1;
    char *v;
    v = strrchr(p,c);
    if (v != NULL) {
        r = 0;
        char* i = p;
        while (v != i) {
            i++;
            r++;
        }
    }
    return r;
}

void String::new_realloc( size_type n) {
    if (n > 0 ) {
        char* pnew = static_cast<char*>(realloc(p, n)); // could return NULL
        if (pnew)
            p = pnew;
    }
}

void String::reserve( const size_type n) {
    if (n >= allocated_ ) {
        this->new_realloc(n + 1);
        allocated_ = n + 1;
    }
}

void String::resize( const size_type n) {
    this->resize( n, 0 );
}

void String::resize( const size_type n, const char c) {
    if (n < size_ ) {
        p[n] = 0;
        size_ = n;
    }
    else if (n >  size_ ) {
        this->reserve( n );
        for (size_type i=size_; i < n; ++i )
            p[i] = c;
        p[n] = 0;
        size_ = n;
    }
}

void String::swap(String& s) {

    // do the swap manually, without relience on std::swap() as that is not always available
    size_t temp;
    char* tempPtr;

    temp = allocated_;
    allocated_ = s.allocated_;
    s.allocated_ = temp;

    temp = size_;
    size_ = s.size_;
    s.size_ = temp;

    tempPtr = p;
    p = s.p;
    s.p = tempPtr;
}


// Comparison
bool operator<( const String& s1, const String& s2 ) {
    return strcmp( s1.c_str(), s2.c_str() ) < 0;
}

void reverse(char s[], uint32_t length)
{
    uint32_t i, j;
    char c;

    for (i = 0, j = length-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

uint32_t itoa_c (int64_t n, char s[])
{
    int64_t sign;
    uint32_t i;

    if ((sign = n) < 0)
        n = -n;

    i = 0;

    do {
        s[i++] = n % 10 + '0';
    }
    while ((n /= 10) > 0);

    if (sign < 0)
        s[i++] = '-';

    s[i] = '\0';

    m2m::reverse(s, i);
    return i;
}

uint8_t* String::convert_integer_to_array(int64_t value, uint8_t &size, const uint8_t *array, const uint32_t array_size)
{
    uint8_t* buffer = NULL;
    size = 0;
    if (array) {
        value = String::convert_array_to_integer(array, array_size);
    }

    if(value < 0xFF) {
        size = 1;
    } else if(value < 0xFFFF) {
        size = 2;
    } else if(value < 0xFFFFFF) {
        size = 3;
    } else if(value < 0xFFFFFFFF) {
        size = 4;
    } else if(value < 0xFFFFFFFFFF) {
        size = 5;
    } else if(value < 0xFFFFFFFFFFFF) {
        size = 6;
    } else if(value < 0xFFFFFFFFFFFFFF) {
        size = 7;
    } else {
        size = 8;
    }

    buffer = (uint8_t*)malloc(size);
    if (buffer) {
        for (int i = 0; i < size; i++) {
            buffer[i] = (value >> ((size - i - 1) * 8));
        }
    } else {
        size = 0;
    }
    return buffer;
}

int64_t String::convert_array_to_integer(const uint8_t *value, const uint32_t size)
{
    int64_t temp_64 = 0;
    for (int i = size - 1; i >= 0; i--) {
        temp_64 += (uint64_t)(*value++) << i * 8;
    }
    return temp_64;
}

bool String::convert_ascii_to_int(const char *value, size_t length, int64_t &conversion_result)
{
    unsigned int index = 0;

    int64_t result = 0;

    int sign;

    int digit;

    // return value, will be set to true if at least one digit is found
    // and a false is returned if
    // a) no digits found, ie. string is empty
    // b) a non-digit or non-'+' or non-'-' char is found.
    // c) more than one +, - chars are found
    //
    bool success = false;

    // have predictable output value even on error
    conversion_result = 0;

    // the optional sign needs to be the first char
    if ((length > 0) && (value[index] == '+')) {
        sign = 1;
        index++;
    } else if ((length > 0) && (value[index] == '-')) {
        sign = -1;
        index++;
    } else {
        sign = 1;
    }

    while ((index < length) && (value[index] != 0)) {

        const char c = value[index++];

        switch (c) {

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                digit = c - '0';
                result *= 10;
                result += digit;
                success = true; // at least one digit was converted successfully
                break;

            // there can be only one sign char and it must be the first
            case '+':
            case '-':
            default:
                // Note: the handling of having a number with digits in front and
                // non-digits at end (eg. "0zero") differs from sscanf() on glibc,
                // as sscanf will return what it got converted and a success value
                // even if the string ended with junk.
                conversion_result = 0;
                return false;
        }
    }

    // put the sign in place
    result *= sign;

    // and pass the result to caller
    conversion_result = result;

    return success;
}

bool String::convert_ascii_to_float(const char *value, size_t size, float &conversion_result)
{
    if (size > REGISTRY_FLOAT_STRING_MAX_LEN) {
        return false;
    }
    char valueArray[REGISTRY_FLOAT_STRING_MAX_LEN + 1];
    for (size_t i=0; i<size; i++) {
        valueArray[i] = *(value +i);
    }
    valueArray[size] = '\0';
    char *end_ptr;
    conversion_result = strtof(valueArray, &end_ptr);
    return *end_ptr == '\0';
}

} // namespace
