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

#if (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_COAP_DOWNLOAD)

#define TRACE_GROUP "FOTA"

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include "fota/fota_fw_download.h"
#include "fota/fota_source.h"

int fota_download_init(void **download_handle)
{
    (void)download_handle;  // unused
    return FOTA_STATUS_SUCCESS;
}

int fota_download_start(void *download_handle, const char *payload_url, size_t payload_offset)
{
    (void)download_handle;  // unused
    return fota_source_firmware_request_fragment(payload_url, payload_offset);
}

int fota_download_request_next_fragment(void *download_handle, const char *payload_url, size_t payload_offset)
{
    (void)download_handle;  // unused
    return fota_source_firmware_request_fragment(payload_url, payload_offset);
}

void fota_download_deinit(void **download_handle)
{
    *download_handle = NULL;
}


#endif  // MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_COAP_DOWNLOAD

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
