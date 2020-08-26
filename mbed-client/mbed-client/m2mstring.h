/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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
#ifndef M2M_STRING_H
#define M2M_STRING_H

/** \file m2mstring.h \brief header for m2m::String */

#include <stddef.h> // size_t
#include <stdint.h>

class Test_M2MString;

/*! \namespace m2m
* \brief Namespace defined as replace for components defined under std namespace.
   */
namespace m2m
{


  /** A simple C++ string class, used as replacement for std::string. */
  class String
  {
    char* p;           ///< The data.
    size_t allocated_;  ///< The allocated memory size (including trailing NULL).
    size_t size_;       ///< The currently used memory size (excluding trailing NULL).

  public:
    typedef size_t size_type;
    static const size_type npos;

    String();
    ~String();
    String(const String&);
    String(const char*);
    String(const char*, size_t);

    String& operator=(const char*);
    String& operator=(const String&);

    String& operator+=(const String&);
    String& operator+=(const char*);
    String& operator+=(char);
    void push_back(char);

    bool operator==(const char*) const;
    bool operator==(const String&) const;

    void clear();       // Set the string to empty (memory remains reserved).

    size_type size()   const   { return size_; }   ///< size without terminating NULL
    size_type length() const   { return size_; }   ///< as size()

    size_type capacity() const { return allocated_-1; }

    bool empty() const    { return size_ == 0; }

    const char* c_str() const { return p; } ///< raw data

    /** Reserve internal string memory so that n characters can be put into the
        string (plus 1 for the NULL char). If there is already enough memory,
        nothing happens, if not, the memory is realloated to exactly this
        amount.
        */
    void reserve( size_type n);

    /** Resize string. If n is less than the current size, the string is truncated.
        If n is larger, the memory is reallocated to exactly this amount, and
        the additional characters are NULL characters.
        */
    void resize( size_type n);

    /** Resize string. If n is less than the current size, the string is truncated.
        If n is larger, the memory is reallocated to exactly this amount, and
        the additional characters are c characters.
        */
    void resize( size_type n, char c);

    /// swap contents
    void swap( String& );

    String substr(const size_type pos, size_type length) const;

    // unchecked access:
    char& operator[](const size_type i)       { return p[i]; }
    char operator[](const size_type i) const { return p[i]; }
    // checked access:
    char at(const size_type i) const;

    /// erase len characters at position pos
    String& erase(size_type pos, size_type len);
    /// Append n characters of a string
    String& append(const char* str, size_type n);

    // Append n characters of a non-zero-terminated string
    // (in contrast with other append(), which performs strlen() for the given string).
    String& append_raw(const char*, size_type);

    // convert int to ascii and append it to end of string
    void append_int(int);

    int compare( size_type pos, size_type len, const String& str ) const;
    int compare( size_type pos, size_type len, const char*   str ) const;

    int find_last_of(char c) const;

    static uint8_t* convert_integer_to_array(int64_t value, uint8_t &size, const uint8_t *array = NULL, const uint32_t array_size = 0);
    static int64_t convert_array_to_integer(const uint8_t *value, const uint32_t size);

    /**
     * Convert ASCII representation of a base 10 number to int64. This is needed
     * as sscanf("%lld") or atoll() are not universally available.
     *
     * @param value optionally zero terminated string containing a zero or one
     * sign char ('+' or '-') and a number in base 10 chars, ie. "0..9"
     *
     * @param length chars to convert, must be more or equal than the chars before zero.
     * This is useful for extracting values from non-zero terminated strings.
     *
     * @param conversion_result result of conversion
     *
     * @return will be set to true if at least one digit is found
     * and a false is returned if:
     *  a) no digits found, ie. string is empty
     *  b) a non-digit or non-'+' or non-'-' char is found.
     *  c) more than one +, - chars are found
     *
     * Note: the handling of a number with digits in front and
     * non-digits at end (eg. "0zero") differs from sscanf(),
     * as sscanf will return what it got converted and a success value
     * even if the string ended with junk.
     */
    static bool convert_ascii_to_int(const char *value, size_t length, int64_t &conversion_result);

    /**
     * Convert ASCII representation to float.
     *
     * @param value optionally zero terminated string containing a float value
     *
     * @param length chars to convert, must be more or equal than the chars before zero.
     *
     * @param conversion_result result of conversion
     *
     * @return will be set to true if valid float value is read.
     * If string contain anything else than correctly formated float, false is returned.
     */
    static bool convert_ascii_to_float(const char *value, size_t size, float &conversion_result);

  private:
    // reallocate the internal memory
    void new_realloc( size_type n);
    char* strdup(const char* other);

    friend class ::Test_M2MString;

  };
  // class

  bool operator<(const String&, const String&);

  void reverse(char s[], uint32_t length);

  uint32_t itoa_c (int64_t n, char s[]);
} // namespace


#endif // M2M_STRING_H
