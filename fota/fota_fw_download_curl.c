// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#if (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD)

#define TRACE_GROUP "FOTA"

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include "fota/fota_internal.h"
#include "fota/fota_fw_download.h"
#include "curl/curl.h"

static size_t handle_data_callback(void *buf, size_t size, size_t nmemb, void *stream)
{
    size_t real_data_size = size * nmemb;
    fota_on_fragment(buf, real_data_size);
    return real_data_size;
}

int fota_download_init(void **download_handle)
{
    int ret = curl_global_init(CURL_GLOBAL_ALL);
    if (ret) {
        FOTA_TRACE_ERROR("curl global init failed %d", ret);
        goto fail;
    }

    // init the curl session
    *download_handle = curl_easy_init();
    if (*download_handle == NULL) {
        FOTA_TRACE_ERROR("curl init session failed");
        goto fail;
    }

    return FOTA_STATUS_SUCCESS;

fail:
    return FOTA_STATUS_INTERNAL_ERROR;
}

int fota_download_start(void *download_handle, const char *payload_url, size_t payload_offset)
{
    int res;

    // set URL to get here
    res = curl_easy_setopt(download_handle, CURLOPT_URL, payload_url);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt url failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Switch on full protocol/debug output while testing
    res = curl_easy_setopt(download_handle, CURLOPT_VERBOSE, 0L);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt verbose failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // disable progress meter, set to 0L to enable it
    res = curl_easy_setopt(download_handle, CURLOPT_NOPROGRESS, 1L);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt no progress failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    res = curl_easy_setopt(download_handle, CURLOPT_BUFFERSIZE, MBED_CLOUD_CLIENT_FOTA_CURL_PAYLOAD_SIZE);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt buffer size failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // resuming upload at this position, possibly beyond 2GB
    // curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, resume_position);
    // currently using regular one, resume still at debugging
    res = curl_easy_setopt(download_handle, CURLOPT_RESUME_FROM, payload_offset);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt resume from failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // send all data to this function
    res = curl_easy_setopt(download_handle, CURLOPT_WRITEFUNCTION, handle_data_callback);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl setopt data callback failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // get it
    res = curl_easy_perform(download_handle);
    if (res != CURLE_OK) {
        FOTA_TRACE_ERROR("curl start downloading failed with error %d", res);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;

}

int fota_download_request_next_fragment(void *download_handle, const char *payload_url, size_t payload_offset)
{
    (void)download_handle;  // unused
    (void)payload_url;  // unused
    (void)payload_offset;  // unused

    return FOTA_STATUS_SUCCESS;
}

void fota_download_deinit(void **download_handle)
{
    // cleanup curl stuff
    curl_easy_cleanup((CURL *)(*download_handle));
    curl_global_cleanup();
    *download_handle = NULL;
}

#endif // (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
