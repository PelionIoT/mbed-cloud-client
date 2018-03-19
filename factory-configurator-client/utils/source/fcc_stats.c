// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifdef FCC_MEM_STATS_ENABLED

#include <stdlib.h>
#include <inttypes.h>

#include "fcc_malloc.h"
#include "pv_log.h"

typedef struct {
    uint32_t current_size;      /* Bytes allocated currently */
    uint32_t total_size;        /* Cumulative sum of bytes ever allocated. */
    uint32_t max_peak_size;     /* Max peak allocated at a certain time (e.g.: getting worst case memory usage) */
    uint32_t alloc_cnt;         /* Current number of allocations. */
    uint32_t free_cnt;          /* Current number of frees. */
    uint32_t alloc_fail_cnt;    /* Number of failed allocations. */
} stats_heap_t;

/* Size must be a multiple of 8 to keep alignment */
typedef struct {
    uint32_t size;
    uint32_t pad;
} alloc_info_t;

static stats_heap_t g_fcc_heap_stats = { 0, 0, 0, 0, 0, 0 };

void *fcc_malloc(size_t size)
{
    void *ptr = NULL;
    alloc_info_t *alloc_info = (alloc_info_t *)malloc(sizeof(alloc_info_t) + size);

    if (alloc_info != NULL) {
        alloc_info->size = size;
        ptr = (void *)(alloc_info + 1);

        g_fcc_heap_stats.current_size += size;
        g_fcc_heap_stats.total_size += size;
        g_fcc_heap_stats.alloc_cnt += 1;

        if (g_fcc_heap_stats.current_size > g_fcc_heap_stats.max_peak_size) {
            g_fcc_heap_stats.max_peak_size = g_fcc_heap_stats.current_size;
        }
    } else {
        g_fcc_heap_stats.alloc_fail_cnt += 1;
    }

    return ptr;
}

void fcc_free(void *ptr)
{
    alloc_info_t *alloc_info = NULL;

    if (ptr != NULL) {
        alloc_info = ((alloc_info_t *)ptr) - 1;
        g_fcc_heap_stats.current_size -= alloc_info->size;
        g_fcc_heap_stats.free_cnt += 1;
        free(alloc_info);
    }
}

void fcc_stats_print_summary(void)
{
    // Use printf since this is printed after mbed trace has been destroyed.
    printf("  ********* FCC Heap Statistics *********\n");
    printf("  * Total bytes allocated:           %" PRIu32 "\n", g_fcc_heap_stats.total_size);
    printf("  * Max peak ever allocated:         %" PRIu32 "\n", g_fcc_heap_stats.max_peak_size);
    printf("  * Number of allocation succeeded:  %" PRIu32 "\n", g_fcc_heap_stats.alloc_cnt);
    printf("  * Number of frees succeeded:       %" PRIu32 "\n", g_fcc_heap_stats.free_cnt);
    printf("  * Number of allocation failed:     %" PRIu32 "\n", g_fcc_heap_stats.alloc_fail_cnt);
    printf("  ***************************************\n");
}

#endif //FCC_MEM_STATS_ENABLED
