// ----------------------------------------------------------------------------
// Copyright 2020-2021 Pelion.
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

#include "multicast_config.h"

#if defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)

#if defined(LIBOTA_ENABLED) && (LIBOTA_ENABLED)

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "sn_coap_header.h"
#include "pal.h"
#include "m2mtimer.h"
#include "multicast.h"
#include "mbed-client/m2minterfacefactory.h"
#include "m2mobject.h"
#include "m2mobjectinstance.h"
#include "m2mresource.h"
#include "MbedCloudClient.h"

#include <stdio.h>
#include "sys/inotify.h"  
#include <unistd.h>
#include "eventOS_scheduler.h"
#include "eventOS_event.h"

#include "libota.h"
#include "otaLIB.h"
#include "otaLIB_resources.h"

char g_mesh_network_id[OTA_MAX_MESH_NETWORK_ID_LENGTH] = "MESH_NETWORK_NAME";

#if (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD)
#define MAX_PAYLOAD_SIZE (OTA_MAX_MULTICAST_MESSAGE_SIZE + OTA_FRAGMENT_CMD_LENGTH)
#else
#define MAX_PAYLOAD_SIZE (OTA_MAX_MULTICAST_MESSAGE_SIZE + OTA_FRAGMENT_CMD_LENGTH)
#endif

#define MESH_EVENT_INIT 1
#define MESH_EVENT_PAYLOAD_RECEIVED 2

#define SHARED_FILE_PATH_MAX 256
char g_mesh_shared_file_name[SHARED_FILE_PATH_MAX] = {0};
#define MAX_MESH_NODE_ID_LENGTH 5

void build_mesh_shared_file_name()
{    
    strcpy(g_mesh_shared_file_name, "../");
    strcat(g_mesh_shared_file_name, g_mesh_network_id);
}

void set_simulated_mesh_network_id(const char* net_id)
{
   memcpy(g_mesh_network_id, net_id, OTA_MAX_MESH_NETWORK_ID_LENGTH);
}

#if defined(ARM_UC_MULTICAST_NODE_MODE)
int mesh_node_id = 0;
#endif

void set_mesh_node_id(int node_id)
{
#if defined(ARM_UC_MULTICAST_NODE_MODE)
   mesh_node_id = node_id;
#endif
}

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
int mesh_nodes_number = 10;
void exit_mesh_node() {
}
#endif

void set_mesh_nodes_number(int nodes_number)
{
#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    mesh_nodes_number = nodes_number;
#endif    
}

static void print_buffer(const unsigned char *buf, unsigned int n) {
    tr_debug("buffer:");
    for (int i = 0; i < n; i++)
    {
        printf("%02X,", buf[i]);
    }
    tr_debug("end buffer");
}

int8_t arm_uc_multicast_mesh_simulator_send(ota_ip_address_t *destination, uint16_t count, uint8_t *payload)
{
    (void)destination;
    tr_debug("arm_uc_multicast_mesh_simulator_send, via file %s", g_mesh_shared_file_name);
    size_t bytes_written;
    FILE *fptr = fopen(g_mesh_shared_file_name, "wb");
    if(fptr == NULL)
    {
       tr_error("Error!");
       exit(1);
    }

    tr_debug("Writing payload to file");
    bytes_written = fwrite(payload, 1, count, fptr);
    if (bytes_written != count) {
        tr_error("Writing payload to file failed bytes_written = %zu count = %d", bytes_written, count);
        fclose(fptr);
        return -1;
    }

    tr_debug("Writing payload to file ok, bytes_written = %zu", bytes_written);
    fclose(fptr);
    return 0;
}

#if defined(ARM_UC_MULTICAST_NODE_MODE)

unsigned char global_mesh_buffer[MAX_PAYLOAD_SIZE] = {0};
size_t global_mesh_buffer_length = 0;

int8_t handler_id = -1;

int inotfd;
int watch_desc;
bool exit_thread = false;

void exit_mesh_node()
{
    tr_debug("exit_mesh_node, watch_desc = %d inotfd = %d", watch_desc, inotfd);
    exit_thread = true;
    inotify_rm_watch(inotfd, watch_desc);
}

static bool wait_for_shared_file(const char *sharedfile, uint8_t *output_buf, size_t *output_size) {
    inotfd = inotify_init();
    
    if (inotfd < 0) {
    	perror("Error in inotify_init");
        exit(1);
    }

    tr_info("inotify_add_watch on file: %s", sharedfile);
    watch_desc = inotify_add_watch(inotfd, sharedfile, IN_CLOSE_WRITE);
    tr_debug("inotify_add_watch = %d, inotfd=%d", watch_desc, inotfd);
    if (watch_desc < 0) {
        perror("Error in inotify_add_watch");
        exit(1);
    }

    size_t bufsiz = sizeof(struct inotify_event) + SHARED_FILE_PATH_MAX + 1;
    struct inotify_event* event = (struct inotify_event*)malloc(bufsiz);

    tr_debug("before read");
    /* wait for an event to occur */
    read(inotfd, event, bufsiz);
    if( exit_thread ) {
        tr_debug("exit from wait_for_shared_file");
        close(inotfd);
        return false;
    }

    tr_debug("after read");
    tr_info("!!!read event for file %.*s", event->len, event->name);

    // Read the file 
    FILE *fptr;

    if ((fptr = fopen(sharedfile,"rb")) == NULL){
       tr_error("Error! opening file");
       // Program exits if the file pointer returns NULL.
       exit(1);
    }

    tr_debug("fread");
    size_t bytes_read = fread(output_buf, 1, MAX_PAYLOAD_SIZE, fptr);
    tr_debug("fclose");
    fclose(fptr);
    inotify_rm_watch(inotfd, watch_desc);
    close(inotfd);
    *output_size= bytes_read;
    tr_debug("Read file. %zu bytes_read", bytes_read);
    print_buffer(output_buf, bytes_read);
    tr_debug("Waiting finished.");
    return true;
}

void process_payload()
{
    ota_socket_receive_data((uint16_t)global_mesh_buffer_length, global_mesh_buffer, NULL);
}

void mesh_simulator_event_handler(arm_event_s* event)
{
    tr_debug("mesh_simulator_event_handler -->");

    switch (event->event_type) {
        case MESH_EVENT_INIT:
            // Nothing to do - ce module already initialized
            tr_debug("MESH_EVENT_INIT -->");
            break;
        case MESH_EVENT_PAYLOAD_RECEIVED:
            tr_debug("MESH_EVENT_PAYLOAD_RECEIVED -->");
            process_payload();
            break;
        default:
            // Should never happen
            tr_error("Unsupported event");
    }

}

void publish_mesh_event(uint8_t event_type)
{
    int8_t event_status;

    arm_event_s event = {
        .receiver = handler_id, // ID we got when creating our handler
        .sender = 0, // Which tasklet sent us the event is irrelevant to us 
        .event_type = event_type, // Indicate event type 
        .event_id = 0, // We currently do not need an ID for a specific event - event type is enough
        .data_ptr = 0, // Not needed, data handled in internal structure
        .priority = ARM_LIB_LOW_PRIORITY_EVENT, // Application level priority
        .event_data = 0, // With one certificate this is irrelevant. If allow multiple certificates, This will be a certificate descriptor (index in a CertificateRenewalDataBase list)
    };

    eventOS_scheduler_mutex_wait();
    event_status = eventOS_event_send(&event);
    eventOS_scheduler_mutex_release();
    tr_info("event_status = %d", event_status);
}

void thread_node(void const *arg) {

    tr_debug("In node thread!!!");
    eventOS_scheduler_mutex_wait();
    if (handler_id == -1) { // Register the handler only if it hadn't been registered before
        handler_id = eventOS_event_handler_create(mesh_simulator_event_handler, MESH_EVENT_INIT);
        tr_error("handler_id = %d", handler_id);
    }
    eventOS_scheduler_mutex_release();

    FILE *fptr = fopen(g_mesh_shared_file_name,"r");
    if (fptr != NULL) {
        tr_error("close file not enter here");
        fclose(fptr);
    } else {

        fptr = fopen(g_mesh_shared_file_name, "wb");
        if(fptr == NULL)
        {
            tr_error("Error!");   
            exit(1);             
        }
        tr_debug("close file");
        fclose(fptr);
    }

    while (1) {

        tr_debug("node: Wait for payload from BR");

        if ( !wait_for_shared_file(g_mesh_shared_file_name, global_mesh_buffer, &global_mesh_buffer_length)) {
            tr_debug("node: exit thread_node");
            return;
        }

        publish_mesh_event(MESH_EVENT_PAYLOAD_RECEIVED);
        // state should now be Awaiting download approval
        tr_debug("node: Wait for next payload from BR");
    }
}

#endif
#endif

#endif // defined(LIBOTA_ENABLED) && (LIBOTA_ENABLED)
