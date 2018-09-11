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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include "include/ConnectorClient.h"
#include "include/EstClient.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client-libservice/common_functions.h"

#define TRACE_GROUP "est"

struct enrollment_context_s {
    est_enrollment_result_cb   result_cb;
    uint8_t                    *data;
    size_t                     data_size;
    void*                      context;
};

#define EST_SEN_LWM2M                "est/sen"
#define EST_SEN_URI_FORMAT           "est/%.*s/sen"

#define EST_CERT_CHAIN_VERSION       1

EstClient::EstClient(ConnectorClient& connector_client)
  :_connector_client(connector_client)
{

}


EstClient::~EstClient()
{
}

est_status_e EstClient::est_request_enrollment(const char *cert_name,
                                               const size_t cert_name_length,
                                               uint8_t *csr,
                                               const size_t csr_length,
                                               est_enrollment_result_cb result_cb,
                                               void *context) const
{
    if (csr == NULL || csr_length == 0 || result_cb == NULL) {
        return EST_STATUS_INVALID_PARAMETERS;
    }

    if (_connector_client.m2m_interface() == NULL) {
        return EST_STATUS_INVALID_PARAMETERS;
    }

    enrollment_context_s *ctx = (enrollment_context_s*)malloc(sizeof(enrollment_context_s));
    if (ctx == NULL) {
        return EST_STATUS_MEMORY_ALLOCATION_FAILURE;
    }

    char *uri = make_est_uri(cert_name, cert_name_length);
    if (uri == NULL) {
      free(ctx);
      return EST_STATUS_MEMORY_ALLOCATION_FAILURE;
    }

    ctx->result_cb = result_cb;
    ctx->context = context;
    ctx->data = NULL;
    ctx->data_size = 0;

    _connector_client.m2m_interface()->post_data_request(uri,
                                                         false,
                                                         csr_length,
                                                         csr,
                                                         EstClient::est_post_data_cb,
                                                         EstClient::est_post_data_error_cb,
                                                         (void*)ctx);

    free(uri);

    return EST_STATUS_SUCCESS;
}

char* EstClient::make_est_uri(const char *cert_name,
                              const size_t cert_name_length)
{
    char *uri = NULL;
    size_t uri_len = 0;
    if (cert_name == NULL) {
        // LwM2M certificate
        uri = (char*)malloc(sizeof(EST_SEN_LWM2M));
        if (uri != NULL) {
            strcpy(uri, EST_SEN_LWM2M);
        }
    }
    else {
        // User certificate
        uri_len = snprintf(NULL, 0, EST_SEN_URI_FORMAT, (int)cert_name_length, cert_name);
        uri_len++; // For null terminator
        uri = (char*)calloc(uri_len, sizeof(char));
        if (uri != NULL) {
            snprintf(uri, uri_len, EST_SEN_URI_FORMAT, (int)cert_name_length, cert_name);
        }
    }
    return uri;
}

void EstClient::est_post_data_cb(const uint8_t *buffer,
                                 size_t buffer_size,
                                 size_t total_size,
                                 bool last_block,
                                 void *context)
{
    enrollment_context_s *enrollment_context = static_cast<enrollment_context_s*>(context);
    (void)total_size;
    assert(enrollment_context);

    // Append new buffer to payload
    size_t new_size = enrollment_context->data_size + buffer_size;
    uint8_t *new_buffer = (uint8_t*)malloc(new_size);
    if (!new_buffer) {
        // Memory error!
        return;
    }

    // Copy old data to start of buffer
    if (enrollment_context->data) {
        memcpy(new_buffer, enrollment_context->data, enrollment_context->data_size);
        free(enrollment_context->data);
    }

    // Copy new data to buffer
    memcpy(new_buffer + enrollment_context->data_size, buffer, buffer_size);

    enrollment_context->data = new_buffer;
    enrollment_context->data_size = new_size;

    if (last_block) {
        cert_chain_context_s *cert_ctx = parse_cert_chain(enrollment_context->data, enrollment_context->data_size);
        if (cert_ctx != NULL) {
            enrollment_context->result_cb(EST_ENROLLMENT_SUCCESS, cert_ctx, enrollment_context->context);
        }
        else {
            enrollment_context->result_cb(EST_ENROLLMENT_FAILURE, NULL, enrollment_context->context);
        }

        free(enrollment_context);
    }

}

void EstClient::est_post_data_error_cb(get_data_req_error_t error_code,
                                       void *context)
{
    enrollment_context_s *enrollment_context = static_cast<enrollment_context_s*>(context);
    assert(enrollment_context);
    enrollment_context->result_cb(EST_ENROLLMENT_FAILURE, NULL, enrollment_context->context);
    free(enrollment_context);
}

cert_chain_context_s* EstClient::parse_cert_chain(uint8_t *cert_chain_data,
                                                  uint16_t cert_chain_data_len)
{
    assert(cert_chain_data);
    assert(cert_chain_data_len > 0);

    uint8_t *ptr = cert_chain_data;
    cert_chain_context_s *context = (cert_chain_context_s*)malloc(sizeof(cert_chain_context_s));

    if (context != NULL) {
        bool success = true;
        context->cert_data_context = ptr;
        uint8_t version = *ptr++;
        context->chain_length = *ptr++;
        cert_context_s **next_context_ptr = &context->certs;

        // Check if unknown version
        if (version != EST_CERT_CHAIN_VERSION) {
            success = false;
        }

        // Check overflow
        if (success && ptr - cert_chain_data > cert_chain_data_len) {
            success = false;
            context->chain_length = 0;
        }

        if (success) {
            for (int i = 0; i < context->chain_length; i++) {
                // Parse certificate length (2 bytes)
                uint16_t cert_len = common_read_16_bit(ptr);
                ptr += 2;
                // Check overflow
                if (ptr - cert_chain_data > cert_chain_data_len) {
                    success = false;
                    break;
                }

                // Allocate new certificate context
                *next_context_ptr = (cert_context_s*)malloc(sizeof(cert_context_s));
                if (*next_context_ptr == NULL) {
                    // Error
                    success = false;
                    break;
                }

                // Set cert pointer to correct position in data
                (*next_context_ptr)->cert_length = cert_len;
                (*next_context_ptr)->cert = ptr;

                ptr += cert_len;

                // Check overflow
                if (ptr - cert_chain_data > cert_chain_data_len) {
                    success = false;
                    free(*next_context_ptr);
                    break;
                }

                next_context_ptr = &((*next_context_ptr)->next);
            }
            *next_context_ptr = NULL;
        }

        if (!success) {
            free_cert_chain_context(context);
            context = NULL;
        }
    }

    return context;
}

void EstClient::free_cert_chain_context(cert_chain_context_s *context) {
    if (context) {
        cert_context_s *next_cert = context->certs;
        while (next_cert != NULL) {
            cert_context_s *temp = next_cert->next;
            // Free each cert context, no need to free the cert data in
            // next_cert->cert because it points inside context->cert_data_context
            // which is free'd last
            free(next_cert);
            next_cert = temp;
        }
        free(context->cert_data_context);
        free(context);
    }
}
