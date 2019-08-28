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

#include <stdbool.h>
#include <stdint.h>
#include "sda_status.h"
#include "sda_error_handling.h"
#include "sda_nonce_mgr.h"
#include "sda_macros.h"
#include "pal.h"

/** Self describing nonce structure
* value - the nonce value
* age - the age of the nonce ranged [0 .. SDA_CYCLIC_BUFFER_MAX_SIZE] in the insertion
*       time, 0 means the oldest nonce while SDA_CYCLIC_BUFFER_MAX_SIZE is the youngeset one.
*/
typedef struct {
    uint64_t value;
    uint8_t age;
} nonce_s;


static nonce_s g_nonce_array[SDA_CYCLIC_BUFFER_MAX_SIZE];

#define SDA_NONCE_AGE_YOUNGEST       (SDA_ARRAY_LENGTH(g_nonce_array) - 1)
#define SDA_NONCE_AGE_OLDEST         (0)


/** Evacuates an entry in the array.
*/
static void circ_buf_nonce_clear(nonce_s *element)
{
    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    element->value = 0;
    element->age = 0;

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
}

/** Gets oldest nonce's index in the array.
*
* - Worth case run-time - O(n)
*/
static nonce_s *circ_buf_get_oldest()
{
    int i = 0;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    while (g_nonce_array[i++].age != SDA_NONCE_AGE_OLDEST);

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return &(g_nonce_array[i - 1]);
}

/** Updates the target index with the new nonce element.
*
* - The new element insert is the youngest one.
* - It updates all the nonce ages in the array due to
*   the new element insertion.
* - Worth case run-time - O(n)
*/
static void circ_buf_update_ages(nonce_s *new, uint64_t nonce_new_value)
{
    uint32_t i;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // traverse array and update age individually (if necessary)
    for (i = 0; i < SDA_ARRAY_LENGTH(g_nonce_array); i++) {
        if (g_nonce_array[i].age > new->age) {
            g_nonce_array[i].age--;
        }
    }

    // update array with the new one (value, age)
    new->value = nonce_new_value;
    new->age = SDA_NONCE_AGE_YOUNGEST;

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
}

void circ_buf_insert(uint64_t nonce_value)
{
    nonce_s *nonce_new_p = NULL;

    // traverse the circular buffer perhaps
    // someone request his nonce value and
    // free up some space
    uint32_t i;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    for (i = 0; i < SDA_ARRAY_LENGTH(g_nonce_array); i++) {
        if (g_nonce_array[i].value == 0) {
            nonce_new_p = &g_nonce_array[i];
            break;
        }
    }

    if (nonce_new_p == NULL) {
        // no.. buffer is still full, we have no option
        // but dropping the oldest nonce from the array.
        nonce_new_p = circ_buf_get_oldest();
    }

    circ_buf_update_ages(nonce_new_p, nonce_value);

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
}

static bool circ_buf_delete(uint64_t nonce)
{
    uint32_t i;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    for (i = 0; i < SDA_ARRAY_LENGTH(g_nonce_array); i++) {
        if (g_nonce_array[i].value == nonce) {
            // found it, remove from array
            circ_buf_nonce_clear(&(g_nonce_array[i]));
            return true;
        }
    }

    SDA_LOG_TRACE_FUNC_EXIT("status=false");

    // failed to find the target nonce value
    return false;
}

sda_status_internal_e sda_nonce_init(void)
{
    uint32_t i;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    for (i = 0; i < SDA_ARRAY_LENGTH(g_nonce_array); i++) {
        g_nonce_array[i].value = 0;
        g_nonce_array[i].age = SDA_NONCE_AGE_OLDEST;
    }

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return SDA_STATUS_INTERNAL_SUCCESS;
}

sda_status_internal_e sda_nonce_fini(void)
{
    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return sda_nonce_init();
}

sda_status_internal_e sda_nonce_get(uint64_t *nonce_out)
{
    palStatus_t pal_status = PAL_SUCCESS;
    uint64_t nonce = 0;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SDA_ERR_RECOVERABLE_RETURN_IF((nonce_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Got NULL for nonce_out");

    // generate a fresh nonce values
    pal_status = pal_osRandomBuffer((uint8_t *)&nonce, sizeof(nonce));
    SDA_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), SDA_STATUS_INTERNAL_NONCE_GENERATION_ERROR, "Failed to generate random nonce");
    SDA_ERR_RECOVERABLE_RETURN_IF((nonce == 0), SDA_STATUS_INTERNAL_NONCE_GENERATION_ERROR, "Got zero for random nonce");

    // push to circular buffer
    circ_buf_insert(nonce);

    *nonce_out = nonce;

    SDA_LOG_TRACE_FUNC_EXIT("nonce=%" PRIu64 "status=SDA_STATUS_INTERNAL_SUCCESS", nonce);

    return SDA_STATUS_INTERNAL_SUCCESS;
}

bool sda_nonce_verify_and_delete(uint64_t nonce)
{
    SDA_LOG_TRACE_FUNC_ENTER("nonce=%" PRIu64, nonce);
    SDA_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return circ_buf_delete(nonce);
}
