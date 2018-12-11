// ----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorized under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C)COPYRIGHT 2017 - 2018 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
// ----------------------------------------------------------------------------

#if defined(MBED_HEAP_STATS_ENABLED) || defined(MBED_STACK_STATS_ENABLED)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "mbed_stats.h"
#include "mbed_stats_helper.h"
#include "pal.h"
#include <string.h>
#if MBED_CONF_RTOS_PRESENT
#include "cmsis_os2.h"
#endif

#define MBED_STATS_FILE_NAME "/mbedos_stats.txt"

/**
    Print mbed-os stack and heap usage to stdout and to text file named mbedos_stats.txt.
    Note: Make sure MBED_HEAP_STATS_ENABLED or MBED_STACK_STATS_ENABLED flags are defined
*/
void print_mbed_stats()
{
    palStatus_t pal_result = PAL_SUCCESS;
    // Max size of directory acquired by pal_fsGetMountPoint + file name (including '/') + '\0'
    char file_name[PAL_MAX_FOLDER_DEPTH_CHAR + sizeof(MBED_STATS_FILE_NAME)] = { 0 };

    pal_result = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, file_name);
    if (pal_result != PAL_SUCCESS) {
        return;
    }

    strcat(file_name, MBED_STATS_FILE_NAME);
    FILE *f = fopen(file_name, "wt");
    if (f) {
        // Heap
#if defined(MBED_HEAP_STATS_ENABLED)
        mbed_stats_heap_t heap_stats;
        mbed_stats_heap_get(&heap_stats);
        fprintf(f, "Current heap usage size: %" PRIu32 "\n", heap_stats.current_size);
        printf("Current heap usage size: %" PRIu32 "\n", heap_stats.current_size);
        fprintf(f, "Max heap usage size: %" PRIu32 "\n", heap_stats.max_size);
        printf("Max heap usage size: %" PRIu32 "\n", heap_stats.max_size);
#endif
        // Stacks
#if defined(MBED_STACK_STATS_ENABLED) && defined(MBED_CONF_RTOS_PRESENT)
        int cnt = osThreadGetCount();
        mbed_stats_stack_t *stack_stats = (mbed_stats_stack_t*)malloc(cnt * sizeof(mbed_stats_stack_t));

        if (stack_stats) {
            fprintf(f, "Thread's stack usage:\n");
            printf("Thread's stack usage:\n");
            cnt = mbed_stats_stack_get_each(stack_stats, cnt);
            for (int i = 0; i < cnt; i++) {
                fprintf(f, "Thread: 0x%" PRIx32 ", Stack size: %" PRIu32 ", Max stack: %" PRIu32 "\r\n", stack_stats[i].thread_id, stack_stats[i].reserved_size, stack_stats[i].max_size);
                printf("Thread: 0x%" PRIx32 ", Stack size: %" PRIu32 ", Max stack: %" PRIu32 "\r\n", stack_stats[i].thread_id, stack_stats[i].reserved_size, stack_stats[i].max_size);
            }
            free(stack_stats);
        }
#endif
        fclose(f);
        printf("*****************************\n\n");
    }

}
#endif
