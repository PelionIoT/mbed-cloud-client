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

#include "sda_error_handling.h"
#include "sda_malloc.h"
#include "sda_internal_defs.h"
#include "sda_cose.h"
#include "sda_verification.h"
#include "sda_data_token.h"


sda_status_internal_e sda_helper_init_token_context(sda_string_token_context_s *data_token_ctx, const uint8_t *data_buffer, size_t data_buffer_size, const char *token_delimiter)
{

    //Check parameters
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_ctx == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_token_ctx");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_buffer == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_buffer pointer");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_buffer_size == 0), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_buffer_size");
    SDA_ERR_RECOVERABLE_RETURN_IF((token_delimiter == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid token_delimiter");
    SDA_ERR_RECOVERABLE_RETURN_IF((strlen(token_delimiter) == 0 || strlen(token_delimiter) > SDA_MAX_DELIMITER_SIZE_IN_BYTES), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid token_delimiter size");
    SDA_ERR_RECOVERABLE_RETURN_IF((strlen(token_delimiter) >= data_buffer_size), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Delimeter size is less or equel to data size");

    //Initialize the context
    data_token_ctx->data_buffer = (uint8_t*)data_buffer;
    data_token_ctx->data_buffer_size = data_buffer_size;
    data_token_ctx->next_token_position = 0;
    strcpy(data_token_ctx->token_delimiter, token_delimiter);
    data_token_ctx->token_delimiter_size = strlen(token_delimiter);
    data_token_ctx->is_all_data_processed = false;
    data_token_ctx->is_last_processed_data_was_delimiter = false;

    return SDA_STATUS_INTERNAL_SUCCESS;
}

sda_status_internal_e sda_helper_get_next_data_token(sda_string_token_context_s *data_token_ctx, uint8_t **data_token_out, size_t *data_token_out_size)
{
    static size_t start_of_next_token_pos;
    size_t current_pos = 0;
    bool is_token_found = false;
    size_t not_processed_data_buffer_size = 0;
    int delimiter_index;

    //Check parameters
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_ctx == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_token_ctx");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_ctx->data_buffer == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Token context was not initialzed");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_ctx->is_all_data_processed == true), SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR, "No more potential tokens");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_token_out");
    SDA_ERR_RECOVERABLE_RETURN_IF((data_token_out_size == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid data_token_out_size");

    //Update local variables
    current_pos = data_token_ctx->next_token_position;//Update current position to next potential token
    start_of_next_token_pos = data_token_ctx->next_token_position;//Save start position of next potential token
    not_processed_data_buffer_size = data_token_ctx->data_buffer_size - current_pos;//Update size of not processed data

    //Check data buffer until :
    //1. End of the buffer -> all data was processed
    //2. Token is found
    //3. Size of not processed data less or equal than delimiter size -> no sense to perform additional iteration
    while (current_pos <= data_token_ctx->data_buffer_size && is_token_found == false && data_token_ctx->token_delimiter_size <= not_processed_data_buffer_size) {

        delimiter_index = 0;//Reset delimiter index for the next iteration

        if (data_token_ctx->data_buffer[current_pos] == data_token_ctx->token_delimiter[delimiter_index]) { //In case current char is equal to first delimiter char

            for (delimiter_index = 0; delimiter_index < (int)data_token_ctx->token_delimiter_size; delimiter_index++) { //try to find the delimiter
                if ((data_token_ctx->data_buffer[current_pos + (size_t)delimiter_index] != data_token_ctx->token_delimiter[(size_t)delimiter_index])) {
                    //In case the delimiter is not found update iteration variables and indexes
                    current_pos++;
                    not_processed_data_buffer_size--;
                    data_token_ctx->is_last_processed_data_was_delimiter = false;
                    break;
                }
            }//for loop

            //After this for loop we need to check if we found the delimiter or not
            if (delimiter_index == (int)data_token_ctx->token_delimiter_size) {
                //Delimiter was found 
                if (current_pos > 0 && data_token_ctx->is_last_processed_data_was_delimiter == false) {
                    //If current token in the middle of data buffer (current_pos > 0) and previous processed data wasn't delimeter (data_token_ctx->is_last_processed_data_was_delimiter == false):
                    // we can return a token, update iteration flag
                    is_token_found = true;
                    data_token_ctx->is_last_processed_data_was_delimiter = true;
                } else {
                    //1. If the delimiter was found in the beginning of the data we have no token to return and we need to perform additional iteration.
                    //2. If last processed data was a delimiter we can not define next token and we need to perform additional iteration
                    current_pos = current_pos + data_token_ctx->token_delimiter_size;
                    not_processed_data_buffer_size = not_processed_data_buffer_size - data_token_ctx->token_delimiter_size;
                    start_of_next_token_pos = data_token_ctx->next_token_position = current_pos;
                    data_token_ctx->is_last_processed_data_was_delimiter = true;
                }
            }//delimiter was found

        } else { //current char is not equal to first delimiter char - go to the next iteration
            current_pos++;
            not_processed_data_buffer_size--;
            data_token_ctx->is_last_processed_data_was_delimiter = false;
        }//check of current char
    }//while iteration


    //Return a result of current iteration

    //If the token wasn't found:
    if (is_token_found == false && start_of_next_token_pos == 0) { //In case no token was found and this is the first iteration -  the function returns as token a pointer to data buffer itself

        *data_token_out = data_token_ctx->data_buffer;
        *data_token_out_size = data_token_ctx->data_buffer_size;
        data_token_ctx->is_all_data_processed = true;
        goto exit;

    } else if (is_token_found == false) {
        //In case no token was found :
        //1. and this is not a first iteration - the function returns a pointer to remained data 
        //2. or error in case this is the last iteration and only the delimiter was found
        if (data_token_ctx->data_buffer_size - start_of_next_token_pos > 0) { //The remained data is not a delimiter 
            *data_token_out = data_token_ctx->data_buffer + start_of_next_token_pos;
            *data_token_out_size = data_token_ctx->data_buffer_size - start_of_next_token_pos;
            data_token_ctx->is_all_data_processed = true;
            goto exit;
        } else { //the remained data is delimiter - don't send a buffer
            data_token_ctx->is_all_data_processed = true;
            SDA_ERR_RECOVERABLE_RETURN_IF(true, SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR, "The remained data was delimiter, no token was detected");
        }
    }

    //If the token was found:
    if (is_token_found == true) { //Update out parameters with found token
        *data_token_out = data_token_ctx->data_buffer + start_of_next_token_pos;
        *data_token_out_size = current_pos - data_token_ctx->next_token_position;
    }

    //Update the context's pointer to next potential token
    if (current_pos + data_token_ctx->token_delimiter_size <= data_token_ctx->data_buffer_size) {
        data_token_ctx->next_token_position = current_pos + data_token_ctx->token_delimiter_size; //Update data position to the next potential token
    }

    //In case this is the last iteration update the context
    if (current_pos + data_token_ctx->token_delimiter_size == data_token_ctx->data_buffer_size || current_pos == data_token_ctx->data_buffer_size) {
        data_token_ctx->is_all_data_processed = true;
    }

exit:
    return SDA_STATUS_INTERNAL_SUCCESS;
}

