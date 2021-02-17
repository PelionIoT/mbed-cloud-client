/*-
 * Copyright 2003-2005 Colin Percival
 * Copyright 2012 Matthew Endsley
 * Copyright (c) 2018-2019 ARM Limited
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef BSPATCH_H
#define BSPATCH_H

#include <stdint.h>
#include <stddef.h>

struct bspatch_stream;

// todo compile time assert from some header
#define COMPILE_TIME_ASSERT(condition) _impl_CASSERT_LINE(condition,__LINE__,__FILE__)

#define _impl_PASTE(a,b) a##b
#define _impl_CASSERT_LINE(predicate, line, file) \
    typedef char _impl_PASTE(assertion_failed_##file##_,line)[2*!!(predicate)-1];

#if defined( BS_PATCH_COMPILE_TIME_MEMORY_ALLOC ) && (BS_PATCH_COMPILE_TIME_MEMORY_ALLOC>0)
COMPILE_TIME_ASSERT(BS_PATCH_COMPILE_TIME_MEMORY_ALLOC % sizeof(int64_t) == 0)
#endif

// events used to feed ARM_BS_ProcessPatchEvent
typedef enum {
    EBSAPI_START_PATCH_PROCESSING = 300,
    EBSAPI_READ_PATCH_DONE,
    EBSAPI_READ_OLD_DONE,
    EBSAPI_SEEK_OLD_DONE,
    EBSAPI_WRITE_NEW_DONE
} bs_patch_api_event_t;

typedef enum {
    // errors
    EBSAPI_ERR_INVALID_STATE = -7,
    EBSAPI_ERR_UNEXPECTED_EVENT = -6,
    EBSAPI_ERR_ALREADY_INIT = -5,
    EBSAPI_ERR_OUT_OF_MEMORY        =     -4,
    EBSAPI_ERR_PARAMETERS  =    -3,  /* Values in struct bspatch_stream didn't make sense (callback was NULL, too small buffer_size... */
    EBSAPI_ERR_FILE_IO =    -2, /* One of the read/write calls returned an error. */
    EBSAPI_ERR_CORRUPTED_PATCH = -1,
    // code for sync completion
    EBSAPI_OPERATION_DONE_IMMEDIATELY = 0,
    // returned when patching is ready and no more events are waited
    EBSAPI_PATCH_DONE,
    // used by corresponding BS API functions to indicate asynch completion of operation
    EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER = 400,
    EBSAPI_OPERATION_OLD_FILE_READ_WILL_COMPLETE_LATER,
    EBSAPI_OPERATION_OLD_FILE_SEEK_WILL_COMPLETE_LATER,
    EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER
} bs_patch_api_return_code_t;

typedef struct bspatch_stream bspatch_stream;

// functions pointer prototypes for BS_PATCH_API
typedef bs_patch_api_return_code_t (*read_patch_f)(const bspatch_stream *stream, void *buffer, uint32_t length);
typedef bs_patch_api_return_code_t (*read_old_f)(const bspatch_stream *stream, void *buffer, size_t length);
typedef bs_patch_api_return_code_t (*seek_old_f)(const bspatch_stream *stream, int64_t seek_diff);
typedef bs_patch_api_return_code_t (*write_new_f)(const bspatch_stream *stream, void *buffer, size_t length);

/**
 * Initialize the bspatch control structure.
 * @param stream, a pointer to memory allocated for BsPatch structure. This will need to be valid for life time of patching
 * @param opaque, pointer to anything the implementor of rpf, rof, sof and wnf functions will need. This can be accessed with name opaque
 * bspatch_stream structure that is delivered to each call of rpf, rof, sof and wnf.
 * @param rpf, a function pointer to a function capable in reading patch data
 * @param rof, a function pointer to a function capable reading old file to be patched
 * @param sof, a function pointer to a function capable seeking the position in old file to be patched
 * @param wnf, a function pointer to a function capable writing new resulting file of patching
 */
void ARM_BS_Init(bspatch_stream *stream, void *opaque,
                 read_patch_f rpf, read_old_f rof,
                 seek_old_f sof, write_new_f wnf);

/**
 * Handles patch processing events.
 * @param stream control structure, with callbacks for data i/o
 * @param bsApiEvent @see BsPatchApiEvent, indication of asynch operation completing or EBsAPI_StartPatchProcessing to start patching
 * @return @see BsPatchApiReturnCode. EBsApiPatchDone if success and whole new file has been written, or code indicating asynch completion
 * from one of the API calls or any other non synch success code returned by API
 */
bs_patch_api_return_code_t ARM_BS_ProcessPatchEvent(bspatch_stream *stream, bs_patch_api_event_t bsApiEvent);

/**
 * Gets opaque pointer from BS patch
 * @param stream pointer to relevant bspatch instance
 * @return opaque pointer given to bspatch during initialization with ARM_BS_Init .
 */
void *ARM_BS_GetOpaque(const bspatch_stream *stream);

/**
 * Frees the resources allocated by bspatch
 * @param stream pointer to relevant bspatch instance
 * @return 0
 */
int ARM_BS_Free(bspatch_stream *stream);

#endif
