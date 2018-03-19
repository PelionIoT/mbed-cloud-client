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

#ifndef __PV_ENDIAN_H__
#define __PV_ENDIAN_H__

#include <inttypes.h>


#ifdef __cplusplus
extern "C" {
#endif

/** @file pv_endian.h
 *
 *    Utility functions that treats endianness.
 */


/** Converts a little endian 32 bit integer to the host endianness, in a platform independent manner.
 *
 *  @param le32  [in] 32 bit integer in little endian format.	
 *
 *  @returns
 *	    32 bit integer in host endianness format.
 */
static inline uint32_t pv_le32_to_h(uint32_t le32)
{
    const uint8_t* le32ptr = (uint8_t*)&le32;
    return (le32ptr[0] << 0)  +
           (le32ptr[1] << 8)  +
           (le32ptr[2] << 16) +
           (le32ptr[3] << 24);
}

/** Converts a big endian 32 bit integer to the host endianness, in a platform independent manner.
 *
 *  @param be32  [in] 32 bit integer in big endian format.
 *
 *  @returns
 *      32 bit integer in host endianness format.
 */
static inline uint32_t pv_be32_to_h(uint32_t be32)
{
    const uint8_t* be32ptr = (uint8_t*)&be32;
    return (be32ptr[0] << 24) +
           (be32ptr[1] << 16) +
           (be32ptr[2] << 8)  +
           (be32ptr[3] << 0);
}


/**  Converts a host endianness 32 bit integer to little endian, in a platform independent manner.
 * 
 *    @param host32  [in] 32 bit integer in host endianness format
 *
 *    @returns 
 *        32 bit integer in little endian format.
 */
static inline uint32_t pv_h_to_le32(uint32_t host32)
{
    uint32_t le32;
    uint8_t *le32_ptr = (uint8_t*)&le32;

    le32_ptr[0] = (host32 >> 0)  & 0xff;
    le32_ptr[1] = (host32 >> 8)  & 0xff;
    le32_ptr[2] = (host32 >> 16) & 0xff;
    le32_ptr[3] = (uint8_t)(host32 >> 24) & 0xff;

    /*@-usedef@*/
    // le32 is being initialized through a pointer.
    return le32;
    /*@+usedef@*/
}


/** Converts a host endianness 32 bit integer to big endian, in a platform independent manner.
 *
 *    @param host32  [in] 32 bit integer in host endianness format
 *
 *    @returns
 *       32 bit integer in big endian format.
 */
static inline uint32_t pv_h_to_be32(uint32_t host32)
{
    uint32_t be32;
    uint8_t *be32_ptr = (uint8_t*)&be32;

    be32_ptr[0] = (uint8_t)(host32 >> 24) & 0xff;
    be32_ptr[1] = (host32 >> 16) & 0xff;
    be32_ptr[2] = (host32 >> 8)  & 0xff;
    be32_ptr[3] = (host32 >> 0)  & 0xff;

    /*@-usedef@*/
    // be32 is being initialized through a pointer.
    return be32;
    /*@+usedef@*/
}

#ifdef __cplusplus
}
#endif

#endif  // __PV_ENDIAN_H__

