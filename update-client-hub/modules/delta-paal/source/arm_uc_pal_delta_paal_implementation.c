// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#include "delta-tool-internal/include/bspatch.h"
#include "delta-tool-internal/include/bspatch_private.h" // Seems we need this for bspatch_stream -struct?

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS 1
#endif

#include "update-client-delta-paal/arm_uc_pal_delta_paal_implementation.h"
#include "update-client-delta-paal/arm_uc_pal_delta_paal.h"
#include "update-client-delta-paal/arm_uc_pal_delta_paal_original_reader.h"
#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "update-client-common/arm_uc_common.h"
#include "update-client-hub/source/update_client_hub_state_machine.h"
#include <inttypes.h>
#define FILE_MAGIC "PELION/BSDIFF001"
#define FILE_MAGIC_LEN (sizeof(FILE_MAGIC) - 1)

#ifndef MIN
#define MIN(x,y) (((x)<(y)) ? (x) : (y))
#endif

static const ARM_UC_PAAL_UPDATE *paal_storage_implementation = NULL;

// Upstream / Firmware manager event handler
static ARM_UC_PAAL_UPDATE_SignalEvent_t pal_deltapaal_upstream_event_handler = NULL;

static arm_uc_callback_t arm_uc_deltapaal_event_handler_callback = { 0 };
static arm_uc_callback_t arm_uc_deltapaal_write_async_callback = { 0 };

/**
  *
  * @brief BsPatch related buffer pointers and offset helpers
  */
// to store bspatch original seek diff and use it in original read
static int64_t arm_uc_pal_deltapaal_bspatch_seek_diff = 0;
// to store the offset of full target new file being written
static uint32_t arm_uc_pal_deltapaal_bspatch_new_offset = 0;
// to keep offset how much of incoming buffer we have consumed
static uint32_t arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset = 0;
// lets make this global to have size better visible in compile time
struct bspatch_stream delta_paal_bs_patch;
// to keep pointer to buffer bspatch gives us to read_patch function
static void* bspatch_read_patch_buffer_ptr = NULL;
// to keep length what size buffer bspatch gave into read_patch function
static uint64_t bspatch_read_patch_buffer_length = 0;
// to keep size how much we have remaining to be consumed from buffer bspatch gave into read_patch function
static uint64_t bspatch_read_patch_buffer_remaining = 0;
// to keep pointer to buffer bspatch gives us to write_new function
static void* bspatch_write_new_buffer_ptr = NULL;
// to keep length what size buffer bspatch gave into write_new function
static uint64_t bspatch_write_patch_buffer_length = 0;
// to keep size how much we have remaining to be consumed from buffer bspatch gave into write_new function
static uint64_t bspatch_write_new_buffer_remaining = 0;

// Reference pointer to buffer which is received in Write() from the Hub
static arm_uc_buffer_t *arm_uc_pal_deltapaal_incoming_buf_ref = NULL;
// To keep internal state of which bspatch event is currently going to be completed
static uint32_t arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_START_PATCH_PROCESSING;
// Assume there is process ongoing  only to one output slot
static uint32_t current_slot_id = 0;

// Store the full delta payload size to check when we are in last fragment
static uint64_t delta_patch_full_size = 0;
// Store the full delta payload offset to check when we are in last fragment
static uint64_t delta_patch_full_offset = 0;
// Store the information if current payload being processed is delta or not (pass-through)
static uint8_t delta_incoming = 0;
// Boolean to indicate if payload if delta or not - to be set false if first fragment (offset==0)
// indicates we are receiveing bsdifflz4 payload and we need to process delta
static bool update_payload_full = true;


// Local Buffer to store the outgoing new image buffer
// - stores data temporarily that bspatch gives us for writing but we cannot
//   write into downstream module because we can write only
//   blocks that align to page size (and/or update hub read/write buffers)
// - For Mbed-os targets we optimize this to bspatch buffer size and align with
//   STORAGE_PAGE -size (default 512) but it can be set smaller in app config with:
//   "update-client.storage-page"                : 128,
#if defined(TARGET_LIKE_MBED)

// Check that ARM_UC_DELTAPAAL_WRITE_BUF_SIZE is aligned with the storage page size
#if ((ARM_UC_DELTAPAAL_WRITE_BUF_SIZE % MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) != 0 || (ARM_UC_DELTAPAAL_WRITE_BUF_SIZE < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE))
#error ARM_UC_DELTAPAAL_WRITE_BUF_SIZE must be divisible by the block page size and at least same size with the page size!
#endif

#endif  // TARGET_LIKE_MBED

static uint8_t buffer_temp_outgoing[ARM_UC_DELTAPAAL_WRITE_BUF_SIZE];
static arm_uc_buffer_t outgoing_new_buffer = {
    .size_max = ARM_UC_DELTAPAAL_WRITE_BUF_SIZE,
    .size = 0,
    .ptr = buffer_temp_outgoing
};

static void arm_uc_deltapaal_map_patch_event_to_error_and_signal_error_handler(bs_patch_api_return_code_t patch_return_value);

static int32_t arm_uc_deltapaal_map_patch_event_to_error(bs_patch_api_return_code_t patch_return_value);

/*
 * Global @TODO:
 *
 */

/*************************************************************************************
 * BsPatch related read/write/seek functions
 */

/**
  * @brief arm_uc_deltapaal_original_seek - BsPatch callback function to Seek the original file/image
  * @param stream pointer to bspatch_stream
  * @param seek_diff distance to move the file pointer in original image
  * @return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY (can't fail)
  */
static bs_patch_api_return_code_t arm_uc_deltapaal_original_seek(const struct bspatch_stream* stream, int64_t seek_diff)
{
    //UC_PAAL_TRACE("arm_uc_deltapaal_original_seek %d", seek_diff);
    (void)stream;
    arm_uc_pal_deltapaal_bspatch_seek_diff += seek_diff;

    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_SEEK_OLD_DONE;
    return EBSAPI_OPERATION_DONE_IMMEDIATELY;
}

/**
 * @brief arm_uc_deltapaal_original_read - BsPatch callback function to Read data from the original file/image
 * @param stream pointer to bspatch_stream
 * @param buffer buffer where read data should be stored
 * @param length amount to read
 * @return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY or EBSAPI_OPERATION_DONE_IMMEDIATELY or error code
 */
static bs_patch_api_return_code_t arm_uc_deltapaal_original_read(const struct bspatch_stream* stream, void* buffer,
                    uint64_t length)
{
//    UC_PAAL_TRACE("arm_uc_deltapaal_original_read seek %d size %" PRIu64,
//                   arm_uc_pal_deltapaal_bspatch_seek_diff, length);
//
    int status = -1;
    (void)stream;

    status = arm_uc_deltapaal_original_reader(buffer, length, (uint32_t)arm_uc_pal_deltapaal_bspatch_seek_diff);

    // @todo: Check read lenght: did we get everything ?

    if (status == ERR_NONE) {
        arm_uc_pal_deltapaal_bspatch_seek_diff += length;
        return EBSAPI_OPERATION_DONE_IMMEDIATELY;
    } else {
        UC_PAAL_TRACE("arm_uc_deltapaal_original_read ERROR: status %d", status);
        return EBSAPI_ERR_FILE_IO;
    }

}

/**
 * @brief arm_uc_deltapaal_patch_read - BsPatch callback function to Read Patch/Delta data/payload
 * @param stream pointer to bspatch_stream
 * @param buffer buffer where read the data to
 * @param length amount of data to read
 * @return bs_patch_api_return_code_t EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER or EBSAPI_OPERATION_DONE_IMMEDIATELY or error code
 */
static bs_patch_api_return_code_t arm_uc_deltapaal_patch_read(const struct bspatch_stream* stream, void* buffer,
                      uint64_t length)
{
    //UC_PAAL_TRACE("arm_uc_deltapaal_patch_read : length %" PRIu64, length);
    (void)stream;
    bs_patch_api_return_code_t return_code = EBSAPI_ERR_UNEXPECTED_EVENT;
    uint64_t copy_amount = 0;

    bspatch_read_patch_buffer_ptr = buffer;
    bspatch_read_patch_buffer_length = length;
    bspatch_read_patch_buffer_remaining = length;

    // 1. There is not enough incoming delta data available - store current available data into buffer and wait for next Write()
    if (length > (arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset)) {
        // We need to signal main bspatch-loop we have (in Write?)
        // to break so that we can get more patch data in.
//        UC_PAAL_TRACE("arm_uc_deltapaal_patch_read Need more - not available in hub buf - EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER, remaining need: %"
//                      PRIu64 " available in hub buf: %"
//                      PRIu32,
//                      bspatch_read_patch_buffer_remaining,
//                      arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset);

        copy_amount = (uint64_t)(arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset);

        return_code = EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER;
    // 2. We have data in incoming buffer we can copy that
    } else {
//        UC_PAAL_TRACE("arm_uc_deltapaal_patch_read - available in hub buf - remaining need: %" PRIu64
//                      " avail in hub buf: %"
//                      PRIu32,
//                      bspatch_read_patch_buffer_remaining,
//                      arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset);

        copy_amount = length;

        return_code = EBSAPI_OPERATION_DONE_IMMEDIATELY;
    }
    memcpy(buffer, arm_uc_pal_deltapaal_incoming_buf_ref->ptr+arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset, copy_amount);
    bspatch_read_patch_buffer_remaining -= copy_amount;
    arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset += (uint32_t)copy_amount;

    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_READ_PATCH_DONE;
    return return_code;
}

/**
 * @brief arm_uc_deltapaal_new_write - BsPatch callback function to Write data into the new image
 * @param stream pointer to bspatch_stream
 * @param buffer buffer where piece of new image for write request can be found
 * @param length amount of new image in the buffer
 * @return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY ro EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER or error
 */
static bs_patch_api_return_code_t arm_uc_deltapaal_new_write(const struct bspatch_stream* stream, void* buffer,
                     uint64_t length)
{
    //UC_PAAL_TRACE("arm_uc_deltapaal_new_write");
    (void)stream;
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    bs_patch_api_return_code_t return_code = EBSAPI_ERR_UNEXPECTED_EVENT;
    uint64_t copy_amount = 0;

    bspatch_write_new_buffer_ptr = buffer;
    bspatch_write_patch_buffer_length = length;
    bspatch_write_new_buffer_remaining = length;

    // Possibilities
    // 1. length <= write_buf space avail. -> copy buffer to write_buf and return immediately if write_buf not full.
    //    If write buf full, call write downstream and return later
    // 2. length > write_buf, copy part of buffer to write_buf to make it full and call write downstream and return later
    //    + save ptr to buffer and amount of rest of data to write
    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_WRITE_NEW_DONE;

    if (((uint32_t)(length))<=(outgoing_new_buffer.size_max-outgoing_new_buffer.size)) {
        // 1.
        //UC_PAAL_TRACE("arm_uc_deltapaal_new_write - We can write into outgoing buf - length: %" PRIu64 " outgoing_new_buffer.size: %" PRIu32 , length, outgoing_new_buffer.size);
        //UC_PAAL_TRACE("arm_uc_deltapaal_new_write - length outgoing_new_buffer.size: %d", outgoing_new_buffer.size);
        copy_amount = length;
        return_code = EBSAPI_OPERATION_DONE_IMMEDIATELY; // in case of not full write buffer, if it gets full, see below)
    } else {
        // 2.
        copy_amount = (uint64_t)(outgoing_new_buffer.size_max-outgoing_new_buffer.size);
        UC_PAAL_TRACE("arm_uc_deltapaal_new_write - We can write into outgoing buf PARTLY - length: %" PRIu64
                      "outgoing size/size_max: %" PRIu32
                      " / %" PRIu32
                      " copy_amount %" PRIu64,
                      length,
                      outgoing_new_buffer.size,
                      outgoing_new_buffer.size_max,
                      copy_amount);
        return_code = EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER;
    }

    memcpy(outgoing_new_buffer.ptr+outgoing_new_buffer.size, buffer, copy_amount);
    outgoing_new_buffer.size += (uint32_t)copy_amount;
    bspatch_write_new_buffer_remaining -= copy_amount;

    if((arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset)==0)  {
        UC_PAAL_TRACE("arm_uc_deltapaal_new_write - WE HAVE CONSUMED INCOMING incoming buf size: %" PRIu32, arm_uc_pal_deltapaal_incoming_buf_ref->size);
    }


    //  UC_PAAL_TRACE("arm_uc_deltapaal_new_write outgoing buffer size + new offset: %" PRIu32, outgoing_new_buffer.size+arm_uc_pal_deltapaal_bspatch_new_offset);
    // outgoing buffer is full, write it
    if (outgoing_new_buffer.size==outgoing_new_buffer.size_max) {
        UC_PAAL_TRACE("arm_uc_deltapaal_new_write - We can write into storage - copy_amount: %" PRIu64 " offset: %" PRIu32 " bspatch_write_new_buffer_remaining: %" PRIu64 ,
                      copy_amount,
                      arm_uc_pal_deltapaal_bspatch_new_offset,
                      bspatch_write_new_buffer_remaining);
        // @todo: we need to schedule this Write call?
        result = paal_storage_implementation->Write(current_slot_id, arm_uc_pal_deltapaal_bspatch_new_offset, &outgoing_new_buffer);
        if (result.code!=ERR_NONE) {
            UC_PAAL_TRACE("arm_uc_deltapaal_new_write - ERROR FROM WRITE! result.code: %" PRIu32 , result.code);
            return_code = EBSAPI_ERR_FILE_IO;
        } else {
            arm_uc_pal_deltapaal_bspatch_new_offset += outgoing_new_buffer.size;
            return_code = EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER; // This will come back to our delta-paal event handler
        }
    }

    return return_code;
}

/*************************************************************************************
 * Internal delta-paal functions
 */

/**
 * @brief arm_uc_deltapaal_reset_internals - Reset internal variables for re-entrancy
 */
static void arm_uc_deltapaal_reset_internals(void)
{
    UC_PAAL_TRACE("arm_uc_deltapaal_reset_internals");
    arm_uc_pal_deltapaal_bspatch_seek_diff = 0;
    arm_uc_pal_deltapaal_bspatch_new_offset = 0;
    arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset = 0;
    bspatch_read_patch_buffer_ptr = NULL;
    bspatch_read_patch_buffer_length = 0;
    bspatch_read_patch_buffer_remaining = 0;
    bspatch_write_new_buffer_ptr = NULL;
    bspatch_write_patch_buffer_length = 0;
    bspatch_write_new_buffer_remaining = 0;

    arm_uc_pal_deltapaal_incoming_buf_ref = NULL;
    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_START_PATCH_PROCESSING;
    current_slot_id = 0;

    delta_patch_full_size = 0;
    delta_patch_full_offset = 0;
    delta_incoming = 0;
    update_payload_full = true;
    outgoing_new_buffer.size = 0;
}

/**
 * @brief arm_uc_deltapaal_signal_ucfm_handler
 * @details Forward event to Upstream / Firmware manager event handler
 * @param event forwarded event
 */
static void arm_uc_deltapaal_signal_ucfm_handler(uintptr_t event)
{
    if (pal_deltapaal_upstream_event_handler) {
        pal_deltapaal_upstream_event_handler(event);
    } else {
        UC_PAAL_ERR_MSG("arm_uc_deltapaal_signal_ucfm_handler ERROR: handler not set!");
    }
}

/**
 * @brief arm_uc_deltapaal_internal_event_handler
 * @details Handle events from downstream PAAL-module
 * @param event this handles only ARM_UC_PAAL_EVENT_WRITE_DONE
 */
static void arm_uc_deltapaal_internal_event_handler(uintptr_t event)
{
    UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler %" PRIxPTR, event);
    bs_patch_api_return_code_t bs_result = EBSAPI_ERR_UNEXPECTED_EVENT;
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    switch (event) {
    // Here we should handle the WRITE_DONE from downstream and continue bspatch proxessing, save and/or
    // return upstream to continue to the next fragments (get new input delta data)
        case ARM_UC_PAAL_EVENT_WRITE_DONE:
            // If bspatch's write buffer had some left overs
            // then copy those here to our internal out buf
            if (!delta_incoming) {
                // this was not delta package write, just report forwards
                arm_uc_deltapaal_signal_ucfm_handler(event);
                break;
            }

            UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler - WRITE DONE remaining %"
                          PRIu64 "delta_patch_full_size %"
                          PRIu64 " delta_patch_full_offset %"
                          PRIu64 " arm_uc_pal_deltapaal_incoming_buf_ref->size %"
                          PRIu32 " arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset %"
                          PRIu32 " outgoing_new_buffer.size %"
                          PRIu32,
                          bspatch_write_new_buffer_remaining,
                          delta_patch_full_size ,
                          delta_patch_full_offset,
                          arm_uc_pal_deltapaal_incoming_buf_ref->size,
                          arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset,
                          outgoing_new_buffer.size);

            if (bspatch_write_new_buffer_remaining>0 &&
                    bspatch_write_new_buffer_remaining<=outgoing_new_buffer.size_max) {
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler - store leftover buffer data: remaining %"
                              PRIu64 " outgoing_new_buffer.size_max %"
                              PRIu32,
                              bspatch_write_new_buffer_remaining,
                              outgoing_new_buffer.size_max);
                outgoing_new_buffer.size = 0;
                memcpy(outgoing_new_buffer.ptr,
                       (uint8_t*)(bspatch_write_new_buffer_ptr)+(uint32_t)(bspatch_write_patch_buffer_length-bspatch_write_new_buffer_remaining),
                      (uint32_t) bspatch_write_new_buffer_remaining);
                outgoing_new_buffer.size = (uint32_t)bspatch_write_new_buffer_remaining;
                bspatch_write_new_buffer_remaining = 0;
            } else if (bspatch_write_new_buffer_remaining>outgoing_new_buffer.size_max)  {
                outgoing_new_buffer.size = 0;
                // this should trigger new full write as we have enough data in bspatch write request buffer already
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler - Too much data still new write request needed buffremaining %" PRIu64, bspatch_write_new_buffer_remaining);
                uint64_t copy_amount = outgoing_new_buffer.size_max;
                memcpy(outgoing_new_buffer.ptr,
                        (uint8_t*)(bspatch_write_new_buffer_ptr)+(uint32_t)(bspatch_write_patch_buffer_length-bspatch_write_new_buffer_remaining),
                        copy_amount);

                outgoing_new_buffer.size += (uint32_t)copy_amount;
                bspatch_write_new_buffer_remaining -= copy_amount;

                result = paal_storage_implementation->Write(current_slot_id, arm_uc_pal_deltapaal_bspatch_new_offset, &outgoing_new_buffer);
                if (result.code!=ERR_NONE) {
                    UC_PAAL_TRACE("arm_uc_deltapaal_buff_still_full_write - ERROR FROM WRITE! result.code: %" PRIu32 , result.code);
                    arm_uc_deltapaal_signal_ucfm_handler(ARM_UC_PAAL_EVENT_WRITE_ERROR);
                    break; // no point to continue if writing fails
                } else {
                    arm_uc_pal_deltapaal_bspatch_new_offset += outgoing_new_buffer.size;
                    break;  // we should now wait for write to complete
                }
            } else if (outgoing_new_buffer.size<outgoing_new_buffer.size_max) {
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler - ELSE need to keep outgoing_new_buffer intact for next call");
            } else {
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler - ELSE2 resetting the outgoing_new_buffer.size, remaining %" PRIu64,
                              bspatch_write_new_buffer_remaining);
                outgoing_new_buffer.size = 0;
            }

            if ((arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset)>0 ||
                    (delta_patch_full_size==delta_patch_full_offset && arm_uc_pal_deltapaal_nextEventToPostToBsPatch != EBSAPI_PATCH_DONE)) {
                // There is still stuff in incoming buffer to get processed, so continue to bspatch do not return to hub
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler going to ProcessPatchEvent with %d", arm_uc_pal_deltapaal_nextEventToPostToBsPatch);
                bs_result = ARM_BS_ProcessPatchEvent(&delta_paal_bs_patch, arm_uc_pal_deltapaal_nextEventToPostToBsPatch);
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler ProcessPatchEvent returned with %d", bs_result);

                if (bs_result==EBSAPI_PATCH_DONE) {
                    // This is needed in case Processpatch returns with DONE but the buffer was not full and written from write_new
                    // @todo do we need to schedule this?
                    UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler going to downstream Write() with offset %"
                                  PRIu32 " size: %"
                                  PRIu32,
                                  arm_uc_pal_deltapaal_bspatch_new_offset,
                                  outgoing_new_buffer.size);
                    result = paal_storage_implementation->Write(current_slot_id, arm_uc_pal_deltapaal_bspatch_new_offset, &outgoing_new_buffer);
                    if (result.code==ERR_NONE) {
                        arm_uc_pal_deltapaal_bspatch_new_offset += outgoing_new_buffer.size;
                    }
                    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_PATCH_DONE;
                } else if (bs_result==EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER) {
                    // If here we get EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER it means we need to get more from hub?
                    UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler Returning with size%" PRIu32 , arm_uc_pal_deltapaal_incoming_buf_ref->size);
                    arm_uc_deltapaal_signal_ucfm_handler(event);
                } else if (bs_result==EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER) {
                    UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER outgoing_new_buffer size %"
                                  PRIu32 " remaining in incoming: %"
                                  PRIu32,
                                  outgoing_new_buffer.size,
                                  arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset);
                    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_WRITE_NEW_DONE;

                } else if (bs_result<0) {
                    UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler Returning with error: %d", bs_result);
                    ARM_BS_Free(&delta_paal_bs_patch);
                    arm_uc_deltapaal_map_patch_event_to_error_and_signal_error_handler(bs_result);
                }
                // @todo: else here?
            } else {
                // Everything is used, go back to hub
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler else branch going to hub with internal outgoing buf size: %" PRIu32 ,
                              outgoing_new_buffer.size);
                UC_PAAL_TRACE("arm_uc_deltapaal_internal_event_handler else branch going to hub with hub incoming buf size: %" PRIu32 ,
                              arm_uc_pal_deltapaal_incoming_buf_ref->size);
                arm_uc_deltapaal_signal_ucfm_handler(event);
            }
            break;
        default:
            /* pass all other events directly */
            arm_uc_deltapaal_signal_ucfm_handler(event);
            break;
    }
}

static void arm_uc_deltapaal_map_patch_event_to_error_and_signal_error_handler(bs_patch_api_return_code_t patch_return_value)
{

    if(patch_return_value >= 0)
    {
        return; // this is not error nothing to do here
    }else
    {
        uintptr_t event = arm_uc_deltapaal_map_patch_event_to_error(patch_return_value);
        arm_uc_deltapaal_signal_ucfm_handler(event);
    }
}


static int32_t arm_uc_deltapaal_map_patch_event_to_error(bs_patch_api_return_code_t patch_return_value)
{
    int32_t event = ARM_UC_PAAL_EVENT_WRITE_ERROR;
    switch (patch_return_value) {
        case EBSAPI_ERR_INVALID_STATE:
            event = ARM_UC_PAAL_EVENT_INITIALIZE_ERROR;
            break;
        case EBSAPI_ERR_UNEXPECTED_EVENT:
            break;
        case EBSAPI_ERR_ALREADY_INIT:
            break;
        case EBSAPI_ERR_OUT_OF_MEMORY:
            event = ARM_UC_PAAL_EVENT_PROCESSOR_INSUFFICIENT_MEMORY_SPACE;
            break;
        case EBSAPI_ERR_PARAMETERS:
            break;
        case EBSAPI_ERR_FILE_IO:
            event = ARM_UC_PAAL_EVENT_READ_ERROR;
            // or
            // ARM_UC_PAAL_EVENT_WRITE_ERROR
            break;
        case EBSAPI_ERR_CORRUPTED_PATCH:
            event = ARM_UC_PAAL_EVENT_PROCESSOR_PARSE_ERROR;
            break;
        default:
            UC_PAAL_TRACE("arm_uc_deltapaal_map_patch_event_to_error unknown error %d", patch_return_value);
            break;
    }
    return event;
}

/**
 * @brief ARM_UC_DeltaPaal_PALEventHandler
 * @param event to be posts from callback to event loop
 */
static void ARM_UC_DeltaPaal_PALEventHandler(uintptr_t event)
{
    UC_PAAL_TRACE("ARM_UC_DeltaPaal_PALEventHandler %" PRIxPTR, event);
    /* decouple event handler from callback */
    ARM_UC_PostCallback(&arm_uc_deltapaal_event_handler_callback,
                        arm_uc_deltapaal_internal_event_handler, event);
}


/**
 * @brief ARM_UC_DeltaPaal_AsyncWrite_Handler
 * @param event ignored
 * @details Asynchronous Write handling for Incoming Delta buffer
 */

static void ARM_UC_DeltaPaal_AsyncWrite_Handler(uintptr_t event)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    bs_patch_api_return_code_t bs_result = EBSAPI_ERR_UNEXPECTED_EVENT;
    (void)event;

    UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler %" PRIxPTR, event);
    // Possibilities:
    // 1. BsPatch read_patch was not completed
    if (arm_uc_pal_deltapaal_nextEventToPostToBsPatch == EBSAPI_READ_PATCH_DONE) {
        UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Patch reading continue ");

        // if read_patch was not completed because not enough buffers (amount of data is open)
        // copy from incoming to bspatch read buffer ptr
        // 1. copy what we can fit into bspatch read_patch buffer and put rest into our local buffer

        // if there was Patch reading in process - copy from incoming buf first -
        if (bspatch_read_patch_buffer_remaining>0 ) {
            uint32_t patch_buf_offset = bspatch_read_patch_buffer_length - bspatch_read_patch_buffer_remaining;
            int copySize = MIN(bspatch_read_patch_buffer_remaining, arm_uc_pal_deltapaal_incoming_buf_ref->size);
            memcpy((uint8_t*)(bspatch_read_patch_buffer_ptr)+(patch_buf_offset),
                   arm_uc_pal_deltapaal_incoming_buf_ref->ptr,
                   copySize);

            UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Copied left overs from incoming buffer, size: %" PRIu64 ,bspatch_read_patch_buffer_remaining);
            UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset %" PRIu32 ,arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset);
            arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset += (uint32_t)copySize;
            bspatch_read_patch_buffer_remaining -= copySize;
            result.code = ERR_NONE;
            if(bspatch_read_patch_buffer_remaining > 0)
            {
                ARM_UC_DeltaPaal_PALEventHandler(ARM_UC_PAAL_EVENT_WRITE_DONE);
                UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler NORMAL incoming buf did not have enough to complete read for remaining of: %" PRIu64 , bspatch_read_patch_buffer_remaining);
                return;
            }
        }


    } else if (arm_uc_pal_deltapaal_nextEventToPostToBsPatch == EBSAPI_WRITE_NEW_DONE) {
        UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Write new continue... ");
        result.code = ERR_NONE;
    } else if (arm_uc_pal_deltapaal_nextEventToPostToBsPatch == EBSAPI_START_PATCH_PROCESSING) {
        UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Patching ");
        result.code = ERR_NONE;
    }

    if (result.code==ERR_NONE) {
        UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger ProcessPatchEvent with event %d", arm_uc_pal_deltapaal_nextEventToPostToBsPatch);

        do {
            bs_result = ARM_BS_ProcessPatchEvent(&delta_paal_bs_patch, arm_uc_pal_deltapaal_nextEventToPostToBsPatch);
            UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger ProcessPatchEvent returned with %d", bs_result);
            if (bs_result==EBSAPI_PATCH_DONE) {
                // In case of processpatchevent returns with DONE but last buffer has not been written, do it here.
                UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger going to downstream write offset: %" PRIu32 " and size %" PRIu32 , arm_uc_pal_deltapaal_bspatch_new_offset, outgoing_new_buffer.size);
                result = paal_storage_implementation->Write(current_slot_id, arm_uc_pal_deltapaal_bspatch_new_offset, &outgoing_new_buffer);
                if (result.code==ERR_NONE) {
                   arm_uc_pal_deltapaal_bspatch_new_offset += outgoing_new_buffer.size;
                }
                ARM_BS_Free(&delta_paal_bs_patch);
                arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_PATCH_DONE;
                break;

            } else if (bs_result==EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER &&
                       delta_patch_full_size>=delta_patch_full_offset) {
                UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger ProcessPatchEvent break out ! with result %d, delta_patch_full_size: %" PRIu64
                              " delta_patch_full_offset: %" PRIu64,
                              bs_result,
                              delta_patch_full_size,
                              delta_patch_full_offset );
                break;
            } else if (bs_result==EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER) {
                UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger ProcessPatchEvent break out ! with result %d", bs_result);
                ARM_UC_DeltaPaal_PALEventHandler(ARM_UC_PAAL_EVENT_WRITE_DONE);
                break;
            }
            else if (bs_result < 0) {
                UC_PAAL_TRACE("ARM_UC_DeltaPaal_AsyncWrite_Handler Trigger ProcessPatchEvent returned with error: %d => return INVALID_STATE error.", bs_result);
                result.code = ERR_INVALID_STATE;
                uintptr_t event = arm_uc_deltapaal_map_patch_event_to_error(bs_result);
                ARM_BS_Free(&delta_paal_bs_patch);
                ARM_UC_DeltaPaal_PALEventHandler(event);
                return;
            }
        } while ((arm_uc_pal_deltapaal_incoming_buf_ref->size-arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset)>0);
    }
}

/*************************************************************************************
 * Public delta-paal functions
 */


/**
 * @brief Set PAAL Update implementation.
 *
 * @param implementation Function pointer struct to implementation.
 * @return Returns ERR_NONE on accept and ERR_INVALID_PARAMETER otherwise.
 */
arm_uc_error_t ARM_UC_DeltaPaal_SetPAALStorage(const ARM_UC_PAAL_UPDATE *implementation)
{
    UC_PAAL_TRACE("ARM_UC_DeltaPaal_SetPAALStorage");
    paal_storage_implementation = implementation;

    return (arm_uc_error_t) { ERR_NONE };
}








/*************************************************************************************
 * ARM_UC_PAAL_UPDATE delta-paal functions
 */



/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Initialize");
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_START_PATCH_PROCESSING;

    if(paal_storage_implementation) {
        if(callback) {
            UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Initialize callback");
            pal_deltapaal_upstream_event_handler = callback;
            // Initialize downstream storage plugin
            // and set deltapaal's eventhandler to downstream
            result = paal_storage_implementation->Initialize(ARM_UC_DeltaPaal_PALEventHandler);
        }
    }

    ARM_BS_Init(&delta_paal_bs_patch, NULL,
                    arm_uc_deltapaal_patch_read,
                    arm_uc_deltapaal_original_read,
                    arm_uc_deltapaal_original_seek,
                    arm_uc_deltapaal_new_write);

    return result;
}

ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UC_PAL_DeltaPaal_GetCapabilities(void)
{
    ARM_UC_PAAL_UPDATE_CAPABILITIES result = {
        .installer_arm_hash = 0,
        .installer_oem_hash = 0,
        .installer_layout   = 0,
        .firmware_hash      = 1,
        .firmware_hmac      = 0,
        .firmware_campaign  = 0,
        .firmware_version   = 1,
        .firmware_size      = 1
    };

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_DeltaPaal_GetMaxID(void)
{
    if(paal_storage_implementation) {
        return paal_storage_implementation->GetMaxID();

    } else {
        return MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
    }
}

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Prepare(uint32_t slot_id,
                                              const arm_uc_firmware_details_t *details,
                                              arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    arm_uc_delta_details_t *delta_details = { 0 };
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Prepare");
    if (paal_storage_implementation && details && buffer) {
        delta_details = ARM_UC_HUB_getDeltaDetails();
        UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Prepare slot %" PRIu32 " size: %" PRIu64
                      " is_delta: %" PRIu8 ,
                      slot_id,
                      details->size,
                      delta_details->is_delta);
        arm_uc_deltapaal_reset_internals();
        delta_incoming = delta_details->is_delta;
        if (delta_incoming) {

            UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Prepare for Delta");
            delta_patch_full_size = delta_details->delta_payload_size;
            ARM_BS_Init(&delta_paal_bs_patch, NULL,
                            arm_uc_deltapaal_patch_read,
                            arm_uc_deltapaal_original_read,
                            arm_uc_deltapaal_original_seek,
                            arm_uc_deltapaal_new_write);

        } else {
            delta_patch_full_size = details->size;
        }

        arm_uc_pal_deltapaal_nextEventToPostToBsPatch = EBSAPI_START_PATCH_PROCESSING;

        UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Prepare delta payload size, delta_patch_full_size: %" PRIu64, delta_patch_full_size );
        result = paal_storage_implementation->Prepare(slot_id,
                                                     details,
                                                     buffer);
    }

    return result;
}

/**
 * @brief Write a fragment to the indicated storage location.
 * @details The storage location must have been allocated using the Prepare
 *          call. The call is expected to write the entire fragment before
 *          signaling completion.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Write(uint32_t slot_id,
                                            uint32_t offset,
                                            const arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    if (buffer == NULL){
        return result;
    }
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write slot %" PRIu32 " offset: %" PRIu32, slot_id, offset);
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write bspatch_read_patch_buffer_length %" PRIu64 " bspatch_read_patch_buffer_remaining: %" PRIu64,
                  bspatch_read_patch_buffer_length,
                  bspatch_read_patch_buffer_remaining);
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write bspatch_write_patch_buffer_length %" PRIu64 " bspatch_write_new_buffer_remaining: %" PRIu64,
                  bspatch_write_patch_buffer_length,
                  bspatch_write_new_buffer_remaining);

    // Save the pointer so that we can access it in patch-read func
    arm_uc_pal_deltapaal_incoming_buf_ref = (arm_uc_buffer_t *)buffer;
    arm_uc_pal_deltapaal_incoming_hub_buf_ref_offset = 0;

    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write arm_uc_pal_deltapaal_incoming_buf_ref->size: %" PRIu32 " size_max: %d" PRIu32, buffer->size, buffer->size_max);

    current_slot_id = slot_id;

    delta_patch_full_offset += buffer->size;

    /* Check whether processing delta or full payload */
    if (offset==0) {
        if (memcmp(buffer->ptr, FILE_MAGIC, FILE_MAGIC_LEN) == 0) {
            update_payload_full = false;
        }
    }

    if((update_payload_full && delta_incoming) || (!update_payload_full && !delta_incoming)) {
        // either prepare said it's delta but it's not or vice versa
        // TODO: report error
    }

    if (!update_payload_full) {
        // Delta processing
        UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write We have DELTA PAYLOAD! ");

        // Decouple to event handler for async handling
        if ( ARM_UC_PostCallback(&arm_uc_deltapaal_write_async_callback,
                                 ARM_UC_DeltaPaal_AsyncWrite_Handler, ARM_UC_PAAL_EVENT_WRITE_DONE) ) {
            result.code = ERR_NONE;
        }

    }
    else if (paal_storage_implementation) {
        // Full image write
        UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Write Going into downstream Write ");

        result = paal_storage_implementation->Write(slot_id, offset, buffer);
    }
    return result;
}

/**
 * @brief Close storage location for writing and flush pending data.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Finalize(uint32_t slot_id)
{
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Finalize offset %" PRIu32,
                 arm_uc_pal_deltapaal_bspatch_new_offset);
    arm_uc_error_t result = { .code = ERR_NONE };

    ARM_BS_Free(&delta_paal_bs_patch);

    if (paal_storage_implementation) {
        result = paal_storage_implementation->Finalize(slot_id);
    }

    return result;
}

/**
 * @brief Read a fragment from the indicated storage location.
 * @details The function will read until the buffer is full or the end of
 *          the storage location has been reached. The actual amount of
 *          bytes read is set in the buffer struct.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Read(uint32_t slot_id,
                                           uint32_t offset,
                                           arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (!buffer) {
        return result;
    }

    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Read offset %" PRIu32 " buffer->size %" PRIu32, offset, buffer->size);

    if (paal_storage_implementation) {
        result = paal_storage_implementation->Read(slot_id, offset, buffer);
    }

    return result;
}

/**
 * @brief Set the firmware image in the slot to be the new active image.
 * @details This call is responsible for initiating the process for
 *          applying a new/different image. Depending on the platform this
 *          could be:
 *           * An empty call, if the installer can deduce which slot to
 *             choose from based on the firmware details.
 *           * Setting a flag to indicate which slot to use next.
 *           * Decompressing/decrypting/installing the firmware image on
 *             top of another.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_Activate(uint32_t slot_id)
{
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_Activate");
    arm_uc_error_t result = { .code = ERR_NONE };

    if (paal_storage_implementation) {
        result = paal_storage_implementation->Activate(slot_id);
    }

    return result;
}

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_GetFirmwareDetails(
    uint32_t slot_id,
    arm_uc_firmware_details_t *details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_GetFirmwareDetails");
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (paal_storage_implementation && details) {
        result = paal_storage_implementation->GetFirmwareDetails(slot_id,
                                                                 details);
    }

    return result;
}

/*****************************************************************************/

/**
 * @brief ARM_UC_PAL_DeltaPaal_GetActiveDetails Gets Active details
 * @details Forwards ARM_UC_PAL_DeltaPaal_GetInstallerDetails-call to  paal_storage_implementation
 *
 * @param details Pointer to arm_uc_installer_details_t details struct to be populated.
 * @return Returns ERR_NONE if null details or paal_storage_implementation or return value from paal_storage_implementation->GetInstallerDetails(details);
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_GetActiveDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_GetActiveDetails");
    if (paal_storage_implementation && details) {
        result = paal_storage_implementation->GetActiveFirmwareDetails(details);
    }

    return result;
}

/**
 * @brief ARM_UC_PAL_DeltaPaal_GetInstallerDetails Get installer details
 * @details Forwards GetInstallerDetails-call to  paal_storage_implementation
 *
 * @param details Pointer to arm_uc_installer_details_t details struct to be populated.
 * @return Returns ERR_NONE if null details or paal_storage_implementation or return value from paal_storage_implementation->GetInstallerDetails(details);
 */
arm_uc_error_t ARM_UC_PAL_DeltaPaal_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_DeltaPaal_GetInstallerDetails");

    if (paal_storage_implementation && details) {
        result = paal_storage_implementation->GetInstallerDetails(details);
    }

    return result;
}


#endif // #if defined(ARM_UC_FEATURE_DELTA_PAAL)
