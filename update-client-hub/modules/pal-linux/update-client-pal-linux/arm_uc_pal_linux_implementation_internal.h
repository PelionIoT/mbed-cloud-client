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

#ifndef ARM_UC_PAL_LINUX_IMPLEMENTATION_INTERNAL_H
#define ARM_UC_PAL_LINUX_IMPLEMENTATION_INTERNAL_H

#include "update-client-paal/arm_uc_paal_update_api.h"

#include <stdbool.h>
#include <stdio.h>

#ifdef PAL_UPDATE_FIRMWARE_DIR
#define ARM_UC_FIRMWARE_FOLDER_PATH PAL_UPDATE_FIRMWARE_DIR
#define ARM_UC_HEADER_FOLDER_PATH PAL_UPDATE_FIRMWARE_DIR
#endif

#ifndef ARM_UC_FIRMWARE_FOLDER_PATH
#define ARM_UC_FIRMWARE_FOLDER_PATH "/tmp"
#endif

#ifndef ARM_UC_HEADER_FOLDER_PATH
#define ARM_UC_HEADER_FOLDER_PATH "/tmp"
#endif

#ifndef ARM_UC_INSTALLER_FOLDER_PATH
#define ARM_UC_INSTALLER_FOLDER_PATH "/tmp"
#endif

#ifndef ARM_UC_USE_EXTERNAL_HEADER
#define ARM_UC_USE_EXTERNAL_HEADER 0
#endif

#define ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH 128
#define ARM_UC_MAXIMUM_COMMAND_LENGTH 256

/* This is the type of the "post_runner" function in the worker struct below.
   This function is called if the worker's command executed succesfully.
   The callback returns the event that the worker will signal. */
typedef int32_t (*arm_ucp_c_runner_t)();

typedef struct {
    const char *command;
    bool header;
    bool firmware;
    bool location;
    bool offset;
    bool size;
    int32_t success_event;
    int32_t failure_event;
    arm_ucp_c_runner_t post_runner;
} arm_ucp_worker_t;

typedef struct {
    arm_ucp_worker_t *activate;
    arm_ucp_worker_t *active_details;
    arm_ucp_worker_t *details;
    arm_ucp_worker_t *finalize;
    arm_ucp_worker_t *initialize;
    arm_ucp_worker_t *installer;
    arm_ucp_worker_t *prepare;
    arm_ucp_worker_t *read;
    arm_ucp_worker_t *write;
} arm_ucp_worker_config_t;

#if defined(TARGET_IS_PC_LINUX)
#include <pthread.h>
typedef struct LinuxWorkerThreadInfo {
    pthread_mutex_t mutex;
    pthread_t       thread;
    pthread_attr_t  attr;
    int             attr_initialized;
} linux_worker_thread_info_t;
#endif

void arm_uc_pal_linux_signal_callback(uint32_t event, bool from_thread);

/* set module variables */
void arm_uc_pal_linux_internal_set_callback(ARM_UC_PAAL_UPDATE_SignalEvent_t callback);
void arm_uc_pal_linux_internal_set_offset(uint32_t offset);
void arm_uc_pal_linux_internal_set_buffer(arm_uc_buffer_t *buffer);
void arm_uc_pal_linux_internal_set_details(arm_uc_firmware_details_t *details);
void arm_uc_pal_linux_internal_set_installer(arm_uc_installer_details_t *details);
void arm_uc_pal_linux_internal_set_location(uint32_t *location);

/* construct file path */
arm_uc_error_t arm_uc_pal_linux_internal_file_path(char *buffer,
                                                   size_t buffer_length,
                                                   const char *folder,
                                                   const char *type,
                                                   uint32_t *location);

/* read firmware header */
arm_uc_error_t arm_uc_pal_linux_internal_read_header(uint32_t *location,
                                                     arm_uc_firmware_details_t *details);

/* read installer header */
arm_uc_error_t arm_uc_pal_linux_internal_read_installer(arm_uc_installer_details_t *details);

/* write firmware header*/
arm_uc_error_t arm_uc_pal_linux_internal_write_header(uint32_t *location,
                                                      const arm_uc_firmware_details_t *details);

/* read file */
arm_uc_error_t arm_uc_pal_linux_internal_read(const char *file_path,
                                              uint32_t offset,
                                              arm_uc_buffer_t *buffer);

/**
 * @brief Function to run script in a worker thread before file operations.
 *
 * @param params Pointer to arm_ucp_worker_t struct.
 */
void *arm_uc_pal_linux_extended_pre_worker(void *params);

/**
 * @brief Function to run script in a worker thread before file operations.
 *
 * @param params Pointer to arm_ucp_worker_t struct.
 */
void *arm_uc_pal_linux_extended_post_worker(void *params);

#endif /* ARM_UC_PAL_LINUX_IMPLEMENTATION_INTERNAL_H */
