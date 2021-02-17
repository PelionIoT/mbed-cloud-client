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

/***
 * TODO:
 *   - change to 32-bit addressing
 */
#include "bspatch.h"
#include "bspatch_private.h"
#include "varint.h"

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

//#define PATCH_STAT_COUNTING 1
#ifndef BS_DEBUG
#define BS_DEBUG 0
#endif

#ifndef BS_HIGH_LEVEL_DEBUG
#define BS_HIGH_LEVEL_DEBUG 0
#endif

#if (BS_DEBUG==1)
// for debug
#include <stdio.h>
#include <assert.h>
#define log(...) printf(__VA_ARGS__)
// for debug end
#else  // remember anything inside assert will not be executed in product code as it is done like this.
// so do not do like assert(readSomething() == true); as things inside assert will not be included in final compile
#define log(...)
#define assert(condition)

#endif // BS_DEBUG

#if BS_DEBUG
//extern int PATCH_TRACING;
#define TRACE_PATCH_CONTROL_READ(...) log(__VA_ARGS__)//PATCH_TRACING = 1;
#else
#define TRACE_PATCH_CONTROL_READ(...)
#endif  // BS_DEBUG

#include "lz4.h"

#define MIN(x,y) (((x)<(y)) ? (x) : (y))

#define DIFF_STR_LEN_X  0
#define EXTRA_STR_LEN_Y 1
#define OLD_FILE_CTRL_OFF_SET_JUMP 2
#define BS_PATCH_HEADERLEN 8

// internal helper functions for BS Patching
bs_patch_api_return_code_t bspatch_readInitialHeaderAndContinue(struct bspatch_stream *stream);

bs_patch_api_return_code_t bspatch_allocWorkingBuffers(struct bspatch_stream *stream);

//int read_controldata(struct bspatch_stream* stream);
//int read_controldata_header(struct bspatch_stream* stream);
int read_controldata_process(struct bspatch_stream *stream);
bs_patch_api_return_code_t sendPatchReadRequest(const struct bspatch_stream *stream, void *buffer, uint32_t length);
bs_patch_api_return_code_t bspatch_readInitialHeaderAndContinueReadOfPatchDone(struct bspatch_stream *stream);
bs_patch_api_return_code_t read_deCompressBuffer_process(struct bspatch_stream *stream, uint32_t frame_len);
//void process_read_frame_len(struct bspatch_stream* stream);
bs_patch_api_return_code_t bspatch_processSingeExtraStrLenCompress(struct bspatch_stream *stream);
int setExpectedExternalEventByState(struct bspatch_stream *stream, int status, bs_patch_state_t nextState,
                                    bs_patch_api_event_t expectedExternalEvent);

// api to hide direct function pointer usage, return code will indicate either async completion synch completion or error
bs_patch_api_return_code_t sendWriteNewRequest(const struct bspatch_stream *stream, void *buffer, size_t length);
bs_patch_api_return_code_t sendSeekOldRequest(const struct bspatch_stream *stream, int64_t seek_diff);
bs_patch_api_return_code_t sendReadOldRequest(const struct bspatch_stream *stream, void *buffer, size_t length);
bs_patch_api_return_code_t bspatch_processDiffBytesPost(struct bspatch_stream *stream);

int isPatchingDone(bspatch_stream *stream);
size_t allignTo8ByteBoundary(size_t address);
bs_patch_api_return_code_t readVarIntEventified(struct bspatch_stream *stream, int isSigned);

#if PATCH_STAT_COUNTING
// note stats counting is now partly broken as varint are not calcualted correctly to header stats
typedef struct {
    uint control_header_count;
    uint control_header_bytes;

    uint control_data_count;
    uint control_data_bytes;

    uint total_diff_str_len_x;
    uint total_extra_str_len_y;

    uint max_compressedDataBuffer;
    uint max_deCompressBuffer;

    uint frame_header_count;
    uint frame_header_bytes;

    uint compressed_frame_count;
    uint compressed_frame_bytes;

    uint non_compressed_frame_count;
    uint non_compressed_frame_bytes;

    uint initial_header_bytes;

}
BsPatchStatistics;

static BsPatchStatistics bsStats = {0};
#include <stdio.h>
#define LOG_STATS printf
void printStats();
void printStats()
{
    /*
     uint initial_header_bytes;
     */
    LOG_STATS("* ********** BS STATS START ***********\n");
    LOG_STATS("* max_compressedDataBuffer: %u max_deCompressBuffer: %u B\n", bsStats.max_compressedDataBuffer, bsStats.max_deCompressBuffer);
    LOG_STATS("* initial_header_bytes %u\n", bsStats.initial_header_bytes);
    LOG_STATS("* ctrlHeader_count %u bytes %u B\n", bsStats.control_header_count, bsStats.control_header_bytes);
    LOG_STATS("* frame_header_count %u frame_header_bytes %u B\n", bsStats.frame_header_count, bsStats.frame_header_bytes);

    LOG_STATS("* compressed_frame_count %u compressed_frame_bytes %u B\n", bsStats.compressed_frame_count, bsStats.compressed_frame_bytes);

    LOG_STATS("* total_diff_str_len_x %u B\n", bsStats.total_diff_str_len_x);
    LOG_STATS("* total_extra_str_len_y %u B\n", bsStats.total_extra_str_len_y);

    uint totalUnCompPayloadBytes = bsStats.total_diff_str_len_x + bsStats.total_extra_str_len_y;
    uint compressionEfficiency = (bsStats.compressed_frame_bytes * 100) / totalUnCompPayloadBytes;
    LOG_STATS("* compressionEfficiency %u %% (smaller is better)\n", compressionEfficiency);

    uint headerBytesSum = bsStats.initial_header_bytes + bsStats.control_header_bytes + bsStats.frame_header_bytes;
    uint headerRatioToCompressedPayload = (headerBytesSum * 100) / bsStats.compressed_frame_bytes;
    LOG_STATS("* headerRatioToCompressedPayload %u %%\n", headerRatioToCompressedPayload);

    LOG_STATS("* ********** BS STATS END ***********\n");

}

#endif

static int64_t offtin(uint8_t *buf)
{
    int64_t y;

    y = buf[7] & 0x7F;
    y = y * 256;
    y += buf[6];
    y = y * 256;
    y += buf[5];
    y = y * 256;
    y += buf[4];
    y = y * 256;
    y += buf[3];
    y = y * 256;
    y += buf[2];
    y = y * 256;
    y += buf[1];
    y = y * 256;
    y += buf[0];

    if (buf[7] & 0x80) {
        y = -y;
    }

    return y;
}

/**
 * Read deCompressBuffer frame from the patch stream using deCompressBuffer as storage, uncompress and store to compressedDataBuffer.
 * @param compressedDataBuffer pre-allocated buffer where undeCompressBuffer frame should be stored
 * @param deCompressBuffer pre-allocated buffer where deCompressBuffer frame can be stored
 * @param stream
 * @param max_compressedDataBuffer length of compressedDataBuffer buffer
 * @param max_deCompressBuffer length of deCompressBuffer buffer
 * @param plain_done the amount of bytes that was dedeCompressBuffer from frame
 * @return 0 if succesfull, BSPATCH error code if failure.
 */
static bs_patch_api_return_code_t read_deCompressBuffer(struct bspatch_stream *stream, uint32_t frame_len)
{
    if (frame_len > stream->max_deCompressBuffer) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }

#if PATCH_STAT_COUNTING

    bsStats.compressed_frame_count += 1;
    bsStats.compressed_frame_bytes += frame_len;
#endif

    return sendPatchReadRequest(stream, stream->bufferForCompressedData, frame_len);
}

// todo not used to anything yeat. made for non compress support
/*
 static int read_unCompressedDataToBuffer(struct bspatch_stream* stream,
 int64_t frame_len) {
 if (frame_len > stream->max_compressedDataBuffer)
 return EBSAPI_ERR_CORRUPTED_PATCH;

 #if PATCH_STAT_COUNTING

 bsStats.non_compressed_frame_count+=1;
 bsStats.non_compressed_frame_bytes+=frame_len;
 #endif

 return sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, frame_len);
 }
 */

bs_patch_api_return_code_t read_deCompressBuffer_process(struct bspatch_stream *stream, uint32_t frame_len)
{
    stream->undeCompressBuffer_len = LZ4_decompress_safe((char *) stream->bufferForCompressedData,
                                                         (char *) stream->nonCompressedDataBuffer, (int)frame_len, (int)stream->max_compressedDataBuffer);

    return stream->undeCompressBuffer_len > 0 ? EBSAPI_OPERATION_DONE_IMMEDIATELY : EBSAPI_ERR_CORRUPTED_PATCH;
}

int read_controldata_process(struct bspatch_stream *stream)
{
#if (BS_HIGH_LEVEL_DEBUG)
    int32_t headerDataSize = stream->nonCompressedDataBuffer[0];
#endif

    if (stream->nonCompressedDataBuffer[0] == 24) {

        stream->ctrl[DIFF_STR_LEN_X] = offtin(stream->bufferForCompressedData);
        stream->ctrl[EXTRA_STR_LEN_Y] = offtin(stream->bufferForCompressedData + 8);
        stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP] = offtin(stream->bufferForCompressedData + 16);
    } else {
        if (LZ4_decompress_safe((char *) stream->bufferForCompressedData, (char *) stream->nonCompressedDataBuffer,
                                stream->nonCompressedDataBuffer[0], 24) != 24) {
            return EBSAPI_ERR_CORRUPTED_PATCH;
        }

        stream->ctrl[DIFF_STR_LEN_X] = offtin(stream->nonCompressedDataBuffer);
        stream->ctrl[EXTRA_STR_LEN_Y] = offtin(stream->nonCompressedDataBuffer + 8);
        stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP] = offtin(stream->nonCompressedDataBuffer + 16);
    }

#if (BS_HIGH_LEVEL_DEBUG)
    printf("read_controldata_process DIFF_STR_LEN_X %" PRId64 " EXTRA_STR_LEN_Y %" PRId64 " OLD_FILE_CTRL_OFF_SET_JUMP %"PRId64" (headerdatasize: %u)\n",
           stream->ctrl[DIFF_STR_LEN_X],
           stream->ctrl[EXTRA_STR_LEN_Y],
           stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP], headerDataSize);
#endif

#if PATCH_STAT_COUNTING
    bsStats.total_diff_str_len_x += stream->ctrl[DIFF_STR_LEN_X];
    bsStats.total_extra_str_len_y += stream->ctrl[EXTRA_STR_LEN_Y];
#endif

    return 0;
}

size_t allignTo8ByteBoundary(size_t address)
{
    if (address % 8 != 0) {
        address += 8 - address % 8;
    }
    return address;
}

bs_patch_api_return_code_t bspatch_allocWorkingBuffers(struct bspatch_stream *stream)
{
    bs_patch_api_return_code_t result = EBSAPI_OPERATION_DONE_IMMEDIATELY;

    if (!stream) {
        return EBSAPI_ERR_PARAMETERS;
    }
    log("bspatch_allocWorkingBuffers max_compressedDataBuffer %u max_deCompressBuffer %u\n",
        stream->max_compressedDataBuffer, stream->max_deCompressBuffer);

#if PATCH_STAT_COUNTING
    bsStats.max_compressedDataBuffer = stream->max_compressedDataBuffer;
    bsStats.max_deCompressBuffer = stream->max_deCompressBuffer;
#endif

#if defined( BS_PATCH_COMPILE_TIME_MEMORY_ALLOC) && (BS_PATCH_COMPILE_TIME_MEMORY_ALLOC > 0)
    if (BS_PATCH_COMPILE_TIME_MEMORY_ALLOC < (stream->max_compressedDataBuffer + stream->max_deCompressBuffer)) {
        log("BS_PATCH_COMPILE_TIME_MEMORY_ALLOC %u < (%u + %u)\n", BS_PATCH_COMPILE_TIME_MEMORY_ALLOC, stream->max_compressedDataBuffer, stream->max_deCompressBuffer);
        return EBSAPI_ERR_OUT_OF_MEMORY;
    }
    stream->nonCompressedDataBuffer = (uint8_t *) allignTo8ByteBoundary((uint64_t) & (stream->bsMemoryBuffer)); // this should already be alligned

    uint32_t diff1 = (uint64_t)stream->nonCompressedDataBuffer - (uint64_t)stream->bsMemoryBuffer;
    (void)diff1;  /* avoid unused warning when log is disabled */
    stream->bufferForCompressedData = ((uint8_t *) & (stream->bsMemoryBuffer)) + stream->max_compressedDataBuffer;


    uint8_t *allignedAdress = (uint8_t *) allignTo8ByteBoundary((uint64_t) stream->bufferForCompressedData);

    uint32_t diff2 = (uint64_t)allignedAdress - (uint64_t)stream->bufferForCompressedData;
    (void)diff2;  /* avoid unused warning when log is disabled */
    stream->bufferForCompressedData = allignedAdress;
    log("align extra1 %u align extra2 %u", diff1, diff2);

    if ((stream->bufferForCompressedData + stream->max_deCompressBuffer)
            > ((uint8_t *) stream) + sizeof(bspatch_stream)) {
        log("not enough memory bufferComp %u decomp %u size %u stream %u allingmentbuffer u%\n",
            stream->bufferForCompressedData, stream->max_deCompressBuffer,
            sizeof(bspatch_stream), (uint32_t)stream, sizeof(stream->allignmentBuffer));
        return EBSAPI_ERR_OUT_OF_MEMORY;
    }
    return result;
#else
    stream->nonCompressedDataBuffer = malloc(stream->max_compressedDataBuffer); // todo these are likely named wrong way
    stream->bufferForCompressedData = malloc(stream->max_deCompressBuffer);

    if (stream->nonCompressedDataBuffer == 0 || stream->bufferForCompressedData == 0) {
        result = EBSAPI_ERR_OUT_OF_MEMORY;
    }
    return result;
#endif // BS_PATCH_COMPILE_TIME_MEMORY_ALLOC
}

bs_patch_api_return_code_t bspatch_processDiffBytesPost(struct bspatch_stream *stream)
{
    /* Adjust pointers */
    stream->newpos += stream->ctrl[DIFF_STR_LEN_X];
    return EBSAPI_OPERATION_DONE_IMMEDIATELY;
}

bs_patch_api_return_code_t bspatch_processSingeExtraStrLenCompress(struct bspatch_stream *stream)
{
    bs_patch_api_return_code_t result = read_deCompressBuffer_process(stream, stream->frame_len);

    if (result) {
        return result;
    }

    return sendWriteNewRequest(stream, stream->nonCompressedDataBuffer, stream->undeCompressBuffer_len);
}

// onle there helpers should access function pointers in BS API
bs_patch_api_return_code_t sendPatchReadRequest(const bspatch_stream *stream, void *buffer, uint32_t length)
{
    return stream->read_patch(stream, buffer, length);
}

bs_patch_api_return_code_t sendSeekOldRequest(const struct bspatch_stream *stream, int64_t seek_diff)
{
    return stream->seek_old(stream, seek_diff);
}

bs_patch_api_return_code_t sendReadOldRequest(const struct bspatch_stream *stream, void *buffer, size_t length)
{
    return stream->read_old(stream, buffer, length);
}

bs_patch_api_return_code_t sendWriteNewRequest(const struct bspatch_stream *stream, void *buffer, size_t length)
{
    return stream->write_new(stream, buffer, length);
}

bs_patch_api_return_code_t bspatch_readInitialHeaderAndContinue(bspatch_stream *stream)
{
    if (stream->read_old == 0 || stream->read_patch == 0 || stream->seek_old == 0 || stream->write_new == 0) {
        return EBSAPI_ERR_PARAMETERS;
    }

    if (stream->new_size == 0) {
        /* First call, read header */
#if PATCH_STAT_COUNTING
        bsStats.initial_header_bytes += FILE_HEADER_LEN;
#endif

        return sendPatchReadRequest(stream, stream->header, FILE_HEADER_LEN);
    } else {
        return EBSAPI_ERR_ALREADY_INIT;
    }
}

bs_patch_api_return_code_t bspatch_readInitialHeaderAndContinueReadOfPatchDone(bspatch_stream *stream)
{
    /* Check for appropriate magic */
    if (memcmp(stream->header, FILE_MAGIC, FILE_MAGIC_LEN) != 0) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }

    /* Read new file length from header */
    int64_t newSize64 = offtin(stream->header + FILE_MAGIC_LEN);
    if (newSize64 < 0 || newSize64 > UINT32_MAX) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }
    stream->new_size = (size_t) newSize64;

    /* Read max undeCompressBuffer frame size from header */
    int64_t max_compressDataBuffer64 = offtin(stream->header + FILE_MAGIC_LEN + 8);
    if (max_compressDataBuffer64 < 0 || max_compressDataBuffer64 > UINT32_MAX) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }
    stream->max_compressedDataBuffer = (uint32_t) max_compressDataBuffer64;

    /* Read max deCompressBuffer frame size from header */
    int64_t max_deCompressBuffer64 = offtin(stream->header + FILE_MAGIC_LEN + 8);

    if (max_deCompressBuffer64 < 0 || max_deCompressBuffer64 > UINT32_MAX) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }
    stream->max_deCompressBuffer = (uint32_t) max_deCompressBuffer64;

    /* Sanity checks */
    if (stream->max_deCompressBuffer > stream->max_compressedDataBuffer || stream->max_compressedDataBuffer < 64
            || stream->max_deCompressBuffer < 1) {
        return EBSAPI_ERR_CORRUPTED_PATCH;
    }
    return EBSAPI_OPERATION_DONE_IMMEDIATELY;
}

int setExpectedExternalEventByState(struct bspatch_stream *stream, int status, bs_patch_state_t nextState,
                                    bs_patch_api_event_t expectedExternalEvent)
{
    if (status < 0) {
        return 1;
    }

    switch (status) {
        case EBSAPI_OPERATION_DONE_IMMEDIATELY:
            stream->next_state = nextState;
            return 0;
        case EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER:
        case EBSAPI_OPERATION_OLD_FILE_READ_WILL_COMPLETE_LATER:
        case EBSAPI_OPERATION_OLD_FILE_SEEK_WILL_COMPLETE_LATER:
        case EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER:
            stream->expectedExternalEvent = expectedExternalEvent;
            stream->next_state = nextState;
            return 1;
        default:
            assert(0);
            return 1;
    }
}

int isPatchingDone(bspatch_stream *stream)
{
    if (stream->new_size != 0 && stream->newpos >= stream->new_size) {
        return 1;
    } else {
        return 0;
    }
}

/// API FUNCTIONS VISIBLE TO OUTSIDE INTERFACE
void ARM_BS_Init(bspatch_stream *stream, void *opaque, read_patch_f rpf, read_old_f rof, seek_old_f sof,
                 write_new_f wnf)
{
    assert(stream && rpf && rof && sof && wnf);
    memset(stream, 0, sizeof(struct bspatch_stream));
    stream->opaque = opaque;
    stream->read_patch = rpf;
    stream->read_old = rof;
    stream->seek_old = sof;
    stream->write_new = wnf;
    stream->expectedExternalEvent = EBSAPI_START_PATCH_PROCESSING;
    stream->next_state = EBsInitial;
    stream->frame_len = 0;
}

/**
 * Main state machine functionality for eventified BS patching. Currently all state transitions are visible inside this
 * function with below helper macros
 */
#define WAIT_FOR_PATCH_DATA(next_state)  \
assert("wrongAssumedStatus" && (status== 0 || status == EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER) || status < 0); \
if(setExpectedExternalEventByState(stream, status, next_state, EBSAPI_READ_PATCH_DONE)) {SET_NEXT_STATE_NOCHECK(next_state);} else {/*internal state transition assumed*/;}

#define WAIT_FOR_SEEK_OLD(next_state)  \
assert("wrongAssumedStatus" && (status== 0 || status == EBSAPI_OPERATION_OLD_FILE_SEEK_WILL_COMPLETE_LATER) || status < 0); \
if (setExpectedExternalEventByState(stream, status, next_state, EBSAPI_SEEK_OLD_DONE)) {SET_NEXT_STATE_NOCHECK(next_state);} else {/*internal state transition assumed*/;}

#define WAIT_FOR_READ_OLD(next_state)  \
assert("wrongAssumedStatus" && (status== 0 || status == EBSAPI_OPERATION_OLD_FILE_READ_WILL_COMPLETE_LATER) || status < 0); \
if (setExpectedExternalEventByState(stream, status, next_state, EBSAPI_READ_OLD_DONE)) {SET_NEXT_STATE_NOCHECK(next_state);} else {/*internal state transition assumed*/;}

#define WAIT_FOR_WRITE_NEW(next_state)  \
assert("wrongAssumedStatus" && (status== 0 || status == EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER) || status < 0); \
if (setExpectedExternalEventByState(stream, status, next_state, EBSAPI_WRITE_NEW_DONE)) {SET_NEXT_STATE_NOCHECK(next_state);} else {/*internal state transition assumed*/;}

#define SET_NEXT_STATE_NOCHECK(new_state) stream->next_state=new_state;

#define SET_NEXT_STATE(new_state) if(status!=0){log ("invalid status %d\n", status);}assert("error status in setting next state" && status==0); SET_NEXT_STATE_NOCHECK(new_state);

bs_patch_api_return_code_t ARM_BS_ProcessPatchEvent(bspatch_stream *stream, bs_patch_api_event_t bsApiEvent)
{
    if (bsApiEvent != stream->expectedExternalEvent) {
        return EBSAPI_ERR_UNEXPECTED_EVENT;
    }

    bs_patch_api_return_code_t status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
    do {
        status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
        //log("bs:state:%d\n", stream->next_state);
        switch (stream->next_state) {
            case EBsInitial:
                TRACE_PATCH_CONTROL_READ("EBsInitial\n");
                status = bspatch_readInitialHeaderAndContinue(stream);
                WAIT_FOR_PATCH_DATA(EBsInitialPatchReadDone)
                break;
            case EBsInitialPatchReadDone:
                status = bspatch_readInitialHeaderAndContinueReadOfPatchDone(stream);
                if (status) {
                    break;
                }
                status = bspatch_allocWorkingBuffers(stream);
                if (status) {
                    break;
                }
                SET_NEXT_STATE(EReadCtrl_diff_str_len)
                break;
            case EReadCtrl_diff_str_len:
                stream->stateAfterReadVarInt = EReadCtrl_extra_str_len_y;

                stream->isSignedVarInt = 0;
                status = sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, 1);
                WAIT_FOR_PATCH_DATA(EBsPatch_process_varintPiece)
                break;
            case EReadCtrl_extra_str_len_y:
                stream->ctrl[DIFF_STR_LEN_X] = stream->var_int;

                stream->stateAfterReadVarInt = EReadCtrl_old_file_ctrl_off_set_jump;
                stream->isSignedVarInt = 0;
                status = sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, 1);
                WAIT_FOR_PATCH_DATA(EBsPatch_process_varintPiece)
                break;
            case EReadCtrl_old_file_ctrl_off_set_jump:
                stream->ctrl[EXTRA_STR_LEN_Y] = stream->var_int;

                stream->stateAfterReadVarInt = EBsReadDataSegment;
                stream->isSignedVarInt = 1;
                status = sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, 1);
                WAIT_FOR_PATCH_DATA(EBsPatch_process_varintPiece)
                break;
            case EBsReadDataSegment:
                stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP] = stream->var_int;
                // Sanity-check
                if (stream->newpos + stream->ctrl[DIFF_STR_LEN_X] > stream->new_size) {
                    status = EBSAPI_ERR_CORRUPTED_PATCH;
                }

                log("DIFF_STR_LEN_X:%ld\n", stream->ctrl[DIFF_STR_LEN_X]);
                log("EXTRA_STR_LEN_Y: %ld\n", stream->ctrl[EXTRA_STR_LEN_Y]);
                log("OLD_FILE_CTRL_OFF_SET_JUMP: %ld\n", stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP]);

                if (stream->ctrl[DIFF_STR_LEN_X] > 0) {
                    stream->total_undeCompressBuffer = 0;
                    SET_NEXT_STATE(EBspatch_processDiffBytes_readHeaderPiece);
                } else {
                    SET_NEXT_STATE(EBsProcessExtraLen);
                }
                break;
            case EBspatch_processDiffBytes_readHeaderPiece:
                TRACE_PATCH_CONTROL_READ("EBspatch_processDiffBytes_readHeaderPiece\n");
                stream->stateAfterReadVarInt = EBspatch_processDiffBytes_processSinglePiece;
                SET_NEXT_STATE(EBspatch_read_frame_len)
                ;
                break;
            case EBspatch_read_frame_len:  // read frame header (encoded with varint so might need multiple rounds)
                stream->isSignedVarInt = 0;
                status = sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, 1);
                WAIT_FOR_PATCH_DATA(EBsPatch_process_varintPiece)
                break;
            case EBspatch_read_varintPiece:
                status = sendPatchReadRequest(stream, stream->nonCompressedDataBuffer, 1);
                WAIT_FOR_PATCH_DATA(EBsPatch_process_varintPiece)
                break;
            case EBsPatch_process_varintPiece:
                status = readVarIntEventified(stream, stream->isSignedVarInt);
                break;
            case EBspatch_processDiffBytes_processSinglePiece:
                TRACE_PATCH_CONTROL_READ("EBspatch_processDiffBytes_processSinglePiece\n");
                stream->frame_len = stream->var_int;
                status = read_deCompressBuffer(stream, stream->frame_len);
                WAIT_FOR_PATCH_DATA(EBspatch_processDiffBytes_processSinglePieceContinue)
                break;
            case EBspatch_processDiffBytes_processSinglePieceContinue:
                status = read_deCompressBuffer_process(stream, stream->frame_len);
                log("extractedSize: %u\n", stream->undeCompressBuffer_len);
                SET_NEXT_STATE(EBspatch_processDiffBytes_processSinglePieceInit)
                break;
            case EBspatch_processDiffBytes_processSinglePieceInit:
                stream->i = 0;
                SET_NEXT_STATE(EBspatch_processDiffBytes_processSinglePieceContinue2)
                break;
            case EBspatch_processDiffBytes_processSinglePieceContinue2:
                if (stream->i < stream->undeCompressBuffer_len) {
                    stream->readRequestSize = 0;
                    uint32_t dataLeft = stream->undeCompressBuffer_len - stream->i;
                    if (stream->max_deCompressBuffer <= dataLeft) {
                        stream->readRequestSize = stream->max_deCompressBuffer;
                    } else {
                        stream->readRequestSize = dataLeft;
                    }
                    status = sendReadOldRequest(stream, stream->bufferForCompressedData, /*1*/stream->readRequestSize);
                    WAIT_FOR_READ_OLD(EBspatch_processDiffBytes_processSinglePieceContinue_writePart); // recursive event to loopify
                } else {
                    status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
                    SET_NEXT_STATE(EBspatch_processDiffBytes_processSinglePieceContinue_postActions);
                }
                break;
            case EBspatch_processDiffBytes_processSinglePieceContinue_writePart:

                for (uint32_t i = 0; i < stream->readRequestSize; i++) {
                    uint8_t newByte = stream->bufferForCompressedData[i]
                                      + stream->nonCompressedDataBuffer[stream->i + i];
                    stream->bufferForCompressedData[i] = newByte;
                }
                status = sendWriteNewRequest(stream, stream->bufferForCompressedData, stream->readRequestSize);
                stream->i += stream->readRequestSize;
                WAIT_FOR_WRITE_NEW(EBspatch_processDiffBytes_processSinglePieceContinue2)
                break;
            case EBspatch_processDiffBytes_processSinglePieceContinue_postActions:
                stream->total_undeCompressBuffer += stream->undeCompressBuffer_len;
                status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
                if (stream->total_undeCompressBuffer < stream->ctrl[DIFF_STR_LEN_X]) {
                    SET_NEXT_STATE(EBspatch_processDiffBytes_readHeaderPiece);
                } else {
                    status = bspatch_processDiffBytesPost(stream);
                    SET_NEXT_STATE(EBsProcessExtraLen);
                }
                break;
            case EBsProcessExtraLen:
                // Sanity-check
                status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
                if (stream->newpos + stream->ctrl[EXTRA_STR_LEN_Y] > stream->new_size) {
                    status = EBSAPI_ERR_CORRUPTED_PATCH;
                    break;
                }

                // Read and write extra string
                if (stream->ctrl[EXTRA_STR_LEN_Y] > 0) {
                    stream->total_undeCompressBuffer = 0;

                    SET_NEXT_STATE(EBsProcessExtraLen_readHeader);
                } else {
                    SET_NEXT_STATE(EBsProcessExtraLen_postStep);
                }
                break;
            case EBsProcessExtraLen_readHeader:
                TRACE_PATCH_CONTROL_READ("EBsProcessExtraLen_readHeader\n");
                stream->stateAfterReadVarInt = EBsProcessExtraLen_singleItem;
                SET_NEXT_STATE(EBspatch_read_frame_len)
                break;
            case EBsProcessExtraLen_singleItem:
                stream->frame_len = stream->var_int;
                TRACE_PATCH_CONTROL_READ("EBsProcessExtraLen_singleItem frame len %llu\n", stream->frame_len);
                status = read_deCompressBuffer(stream, stream->frame_len);
                WAIT_FOR_PATCH_DATA(EBsProcessExtraLen_singleItemContinue)
                break;
            case EBsProcessExtraLen_singleItemContinue:
                status = bspatch_processSingeExtraStrLenCompress(stream);
                WAIT_FOR_WRITE_NEW(EBsProcessExtraLen_singleItemContinuePostStep)
                break;
            case EBsProcessExtraLen_singleItemContinuePostStep:
                stream->total_undeCompressBuffer += stream->undeCompressBuffer_len;

                if (stream->total_undeCompressBuffer < stream->ctrl[EXTRA_STR_LEN_Y]) {
                    SET_NEXT_STATE(EBsProcessExtraLen_readHeader);
                } else {
                    SET_NEXT_STATE(EBsProcessExtraLen_postStep);
                }
                break;
            case EBsProcessExtraLen_postStep:
                // Adjust pointers
                stream->newpos += stream->ctrl[EXTRA_STR_LEN_Y];
                status = sendSeekOldRequest(stream, stream->ctrl[OLD_FILE_CTRL_OFF_SET_JUMP]);
                WAIT_FOR_SEEK_OLD(EReadCtrl_diff_str_len)
                break;

            default:
                assert("unknown state" && 0);
                status = EBSAPI_ERR_INVALID_STATE;
                break;
        }
    } while ((!isPatchingDone(stream) && status == EBSAPI_OPERATION_DONE_IMMEDIATELY));

    if (isPatchingDone(stream)) {
#if PATCH_STAT_COUNTING
        printStats();
#endif

        return EBSAPI_PATCH_DONE;
    } else {
        return status;
    }
}

bs_patch_api_return_code_t readVarIntEventified(struct bspatch_stream *stream, int isSigned)
{
    bs_patch_api_return_code_t status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
    var_int_op_code decode_op;
    if (isSigned) {
        decode_op = decode_signed_varint(*(stream->nonCompressedDataBuffer), (int64_t *) &stream->var_int,
                                         (int)stream->var_int_len);
    } else {
        decode_op = decode_unsigned_varint(*(stream->nonCompressedDataBuffer), &stream->var_int, (int)stream->var_int_len);
    }
    stream->var_int_len++;

    if (stream->var_int_len >= 8 || decode_op < 0) {
        status = EBSAPI_ERR_CORRUPTED_PATCH;
    }

    if (decode_op == OPERATION_NEEDS_MORE_DATA) {
        status = EBSAPI_OPERATION_DONE_IMMEDIATELY;
        SET_NEXT_STATE(EBspatch_read_varintPiece);
    } else {
        stream->var_int_len = 0;
        assert(stream->stateAfterReadVarInt);
        SET_NEXT_STATE(stream->stateAfterReadVarInt); // next state depends on state that started frame len reading
        stream->stateAfterReadVarInt = EBsInitial;
    }
    return status;
}

void *ARM_BS_GetOpaque(const struct bspatch_stream *stream)
{
    return stream->opaque;
}

int ARM_BS_Free(struct bspatch_stream *stream)
{
#if defined( BS_PATCH_COMPILE_TIME_MEMORY_ALLOC) && (BS_PATCH_COMPILE_TIME_MEMORY_ALLOC > 0)
    // nothing to free really but we can lose the pointers at least
    stream->nonCompressedDataBuffer = 0;
    stream->bufferForCompressedData = 0;
#else

    free(stream->nonCompressedDataBuffer);
    free(stream->bufferForCompressedData);
    stream->nonCompressedDataBuffer = 0;
    stream->bufferForCompressedData = 0;
#endif

    return 0;
}
