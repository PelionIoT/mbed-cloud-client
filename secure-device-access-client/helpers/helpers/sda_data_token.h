// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#ifndef __SDA_DATA_TOKEN_H__
#define __SDA_DATA_TOKEN_H__

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "sda_status_internal.h"


#ifdef __cplusplus
extern "C" {
#endif

#define SDA_MAX_DELIMITER_SIZE_IN_BYTES 5

typedef struct sda_string_token_context {
    uint8_t *data_buffer;                                                     //pointer to data buffer
    size_t data_buffer_size;                                                  //data buffer size
    size_t next_token_position;                                               //offset position of next potential token
    char token_delimiter[SDA_MAX_DELIMITER_SIZE_IN_BYTES + 1];                //pointer to delimiter string
    size_t token_delimiter_size;                                              //delimiter size
    bool is_all_data_processed;                                               //this flag indicates if there is more data to process
    bool is_last_processed_data_was_delimiter;                                //this flag indicates if in the last iteration a delimiter was found
}sda_string_token_context_s;


/** Initialize data token context according to passed data. This context will be used in sda_helper_get_next_data_token
 *  to detect pointer and size to the next token, using passed delimiter.The function perform processing on the data_buffer inplace and the user should not free data_buffer memory.
 *
 *    @data_token_ctx[out]    pointer to token data context to initialize
 *    @data_buffer[in]        pointer to data for processing
 *    @data_buffer_size[in]   size of data
 *    @token_delimiter[in]    pointer to delimiter string
 *    @returns
 *       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
 */
sda_status_internal_e sda_helper_init_token_context(sda_string_token_context_s *data_token_ctx, const uint8_t *data_buffer, size_t data_buffer_size, const char *token_delimiter);

/** The function finds and returns pointer and size of next data token.
*
*    @data_token_ctx[in/out]     pointer to token data context
*    @data_token_out[out]        pointer to data for processing
*    @data_token_out_size[out]   size of data
*    @returns
*       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_helper_get_next_data_token(sda_string_token_context_s *data_token_ctx, uint8_t **data_token_out, size_t *data_token_out_size);
#ifdef __cplusplus
}
#endif

#endif  // __SDA_DATA_TOKEN_H__

