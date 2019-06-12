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

#ifndef INCLUDE_BSPATCH_PRIVATE_H_
#define INCLUDE_BSPATCH_PRIVATE_H_


#include "bspatch.h"

/* Patch applied succesfully, but new file is not ready yet. User should re-fill patch buffer and call bspatch again. */
#define BSPATCH_NEED_MORE_PATCH_DATA 1

/* Patch applied succesfully, and new file is fully written. */
#define BSPATCH_DONE 0
#define FILE_MAGIC "PELION/BSDIFF001"
#define FILE_MAGIC_LEN (sizeof(FILE_MAGIC) - 1)

#define CONTROL_LEN (8 * 3)
#define FILE_HEADER_LEN (FILE_MAGIC_LEN + 24)

// internal states of BS patch state machine
typedef enum {
    EBsInitial = 100,
    EBsInitialPatchReadDone,
    EBsAllocWorkingBuffer,
    EBsReadInitialHeader,
    EBsReadControlSegmentHeader,
    EBsReadControlSegment,
    EBsReadDataSegment,
    EBspatch_processDiffBytes_readHeaderPiece,
    EBspatch_processDiffBytes_processSinglePiece,
    EBspatch_processDiffBytes_processSinglePieceContinue,
    EBspatch_processDiffBytes_processSinglePieceInit,
    EBspatch_processDiffBytes_processSinglePieceContinue2,
    EBspatch_processDiffBytes_processSinglePieceContinue_writePart,
    EBspatch_processDiffBytes_processSinglePieceContinue_postActions,

    EBsProcessExtraLen,
    EBsProcessExtraLen_readHeader,
    EBsProcessExtraLen_singleItem,
    EBsProcessExtraLen_singleItemContinue,
    EBsProcessExtraLen_singleItemContinuePostStep,
    EBsProcessExtraLen_postStep,

    EBspatch_read_frame_len,
    EBspatch_read_frame_len_piece_read,
    EBspatch_read_varintPiece,
    EReadCtrl_diff_str_len,
    EReadCtrl_extra_str_len_y,
    EReadCtrl_old_file_ctrl_off_set_jump,
    EBsPatch_process_varintPiece

} bs_patch_state_t;

/* Control structure for bspatch
 *   opaque      Is not used by bspatch but can be used e.g. by caller to store file handle(s).
 *   read_patch  When called, should read next length bytes from the patch file into buffer and return 0 on success.
 *   read_old    When called, should read next length bytes from the base file into buffer and return 0 on success.
 *   seek_old    When called, should reposition the old file with seek_diff amount in relation to current position and return 0 on success.
 *   write_new   When called, should write length bytes from buffer into end of the new file and return 0 on success.
 */
struct bspatch_stream {

    /* To be filled by ARM_BS_Init only thing used outside */
    void* opaque;
    read_patch_f read_patch;
    read_old_f read_old;
    seek_old_f seek_old;
    write_new_f write_new;

    // private members to BS patching. // not to be used by API implementor for other than debug
    int64_t undeCompressBuffer_len;
    int64_t total_undeCompressBuffer; /* keeping track of total undeCompressBuffer bytes */
    uint64_t var_int;
    uint64_t var_int_len;
    uint64_t frame_len;
    int64_t newpos; /* keeping track of position of the resulting file */
    int64_t i;
    int64_t ctrl[3];

    uint8_t* nonCompressedDataBuffer; /* buffer for undeCompressBuffer bytes */
    uint8_t* bufferForCompressedData; /* buffer to store deCompressBuffer frame for decompression */

    uint32_t progress;
    uint32_t new_size;
    // for compress support
    uint32_t max_compressedDataBuffer;
    uint32_t max_deCompressBuffer;
    uint32_t readBufferCurrentSize;
    uint32_t readRequestSize ;
    uint8_t header[FILE_HEADER_LEN];  // potential padding here
    bs_patch_state_t next_state;
    bs_patch_api_event_t expectedExternalEvent;
    bs_patch_state_t stateAfterReadVarInt;
    uint32_t isSignedVarInt;

#if defined( BS_PATCH_COMPILE_TIME_MEMORY_ALLOC ) && (BS_PATCH_COMPILE_TIME_MEMORY_ALLOC>0)
    int64_t bsMemoryBuffer[BS_PATCH_COMPILE_TIME_MEMORY_ALLOC/sizeof(int64_t)];  //
    uint8_t allignmentBuffer[7+7]; // to allow space to alling to 8 byte boundary properly.
#endif
};



#endif /* INCLUDE_BSPATCH_PRIVATE_H_ */
