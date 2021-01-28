// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#include "ds_metrics_report.h"
#include "ds_plat_metrics_report.h"
#include "pv_error_handling.h"
#include <sys/sysinfo.h>
#include <stdio.h> 
#include <sys/sysinfo.h>
#include <netinet/tcp.h>
#include <stdlib.h>

typedef enum {
    UDPV4, 
    TCPV4,
    PROTOCOL_TYPE_MAX
} ds_net_protocol_type_t;

/**
 * @brief Extracts ip data (ip address and ip port) from rem_address linux field.
 * 
 * @param rem_address_field the field in the linux format, in which the remote address is reported in /proc/net{protocol}.
 * @param ip_data_out out put ip data
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, ip_data_out will be filled.  
 */
static ds_status_e extract_ip_addr_and_port(const char *rem_address_field, ds_stat_ip_data_t * ip_data_out);

/**
 * @brief Checks if the linux rem_address should be reported or not.
 * 
 * @param rem_address_field the field in the linux format, in which the remote address is reported in /proc/net{protocol}.
 * @param connection_state_field socket state field, how it reported in /proc/net{protocol}.
 * @param protocol tcp or udp.
 * @return true if the address should not be reported.
 * @return false if the address should be reported.
 */
static bool avoid_report_remote_address(const char *rem_address_field, int connection_state_field, ds_net_protocol_type_t protocol);

/**
 * @brief Checks if the ip address and port already reported.  
 * 
 * @param stats_array array of ip data to search in
 * @param number_items_to_search index of item below which the ip_data can possibly be found (the range includs the index it self).
 *                          Note the rabge is [0, ..., number_items_to_search]
 * @param ip_data ip data to search.
 * @return true if the ip data already exists in the array.
 * @return false if the ip data does not exist in the array.
 */
static bool is_ip_addr_and_port_already_reported(const ds_stat_ip_data_t *stats_array, uint32_t number_items_to_search, const ds_stat_ip_data_t* ip_data);


ds_status_e ds_plat_cpu_stats_get(ds_stats_cpu_t *stats)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((stats == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: stats is NULL");

    FILE* fp = fopen("/proc/uptime", "r");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fp == NULL), DS_STATUS_ERROR, "Failed to open /proc/uptime");

    char *line = NULL; // getline will allocate line according to the required size
    size_t line_len = 0;
    // read 1 line from the file
    ssize_t read_chars = getline(&line, &line_len, fp); // getline always puts \0 at the end
    fclose (fp);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((read_chars == -1), DS_STATUS_ERROR, "Failed to read /proc/uptime");
 
    double uptime; // the number of seconds that have elapsed since the machine was booted.
    double idle_time; // sum of time periods in seconds that each processor has spent idle.

    int items_scanned = sscanf(line, "%lf %lf", &uptime, &idle_time);

    // line was allocated in getline, free it
    free(line);

    // we should read exactly 2 items
    SA_PV_ERR_RECOVERABLE_RETURN_IF((items_scanned != 2), DS_STATUS_ERROR, "Failed to parse /proc/uptime");

    // retrieve number of configured CPU's
    int cpus_num = get_nprocs_conf(); 

    // avoid dividing by zero
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cpus_num == 0), DS_STATUS_ERROR, "Error: get_nprocs_conf returned 0");

    stats->uptime = (uint64_t)uptime;
    stats->idle_time = (uint64_t)(idle_time / cpus_num);

    SA_PV_LOG_TRACE_FUNC_EXIT("uptime=%" PRIu64 ", idletime=%" PRIu64, stats->uptime, stats->idle_time);

    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_thread_stats_get(uint32_t *thread_count_out)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    /* This function counts all light-weight procceses (LWP) in the Linux. The output of the 'ps -eLf --no-heading' is the table 
    of all LWP's in the system without the first heading line. For each LWP there is exacly 1 line in the table, 
    so it's enough to count the number of lines in the output of the command. 'wc -l' counts the number of lines in the table. */

    SA_PV_ERR_RECOVERABLE_RETURN_IF((thread_count_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: thread_count_out is NULL");

    const char command[] = "ps -eLf --no-heading | wc -l";
    // Open the file to which was written output of the command
    FILE *fp = popen(command, "r");

    SA_PV_ERR_RECOVERABLE_RETURN_IF((fp == NULL), DS_STATUS_ERROR, "Failed to run %s", command);

    char *line = NULL;
    size_t line_len = 0;
    // read 1 line from the open file
    ssize_t read_chars = getline(&line, &line_len, fp); // getline always puts \0 at the end

    pclose (fp);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((read_chars == -1), DS_STATUS_ERROR, "Failed to read %s output", command);

    unsigned int threads_num; // the number of light weight threads in system

    int items_scanned = sscanf(line, "%u", &threads_num);

    // line was allocated in getline, free it
    free(line);

    // we should read exactly 1 item
    SA_PV_ERR_RECOVERABLE_RETURN_IF((items_scanned != 1), DS_STATUS_ERROR, "Failed to parse %s output", command);

    // running of 'ps -eLf --no-heading | wc -l' initiates 2 extra proccesses, so we need to substruct 2 from the output of the command
    SA_PV_ERR_RECOVERABLE_RETURN_IF((threads_num <= 2), DS_STATUS_ERROR, "Command %s failed to count threads, count = %u", command, threads_num);

    // substruct 'ps' and 'wc' proccesses from the count of total proccesses
    *thread_count_out = threads_num - 2;

    SA_PV_LOG_TRACE_FUNC_EXIT("thread_count_out=%" PRIu32, *thread_count_out);

    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out)
{
    const unsigned int NOT_USED_FIELD = 0;
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((network_stats_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: network_stats_out is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((stats_count_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: stats_count_out is NULL");

    ds_status_e status = DS_STATUS_SUCCESS;

    // memory allocation stuff
    const uint32_t STAT_ARRAY_BLOCK_SIZE = 10;
    uint32_t stats_array_current_size = 0;
    ds_stats_network_t *stats_array = NULL;

    // placeholder for /proc/net/dev interface name field
    char if_name_field[DS_MAX_INTERFACE_NAME_SIZE];

    // use long long integers in order not to overflow the variable in sscanf
    long long unsigned int received_bytes, transmit_bytes;

    // fields not used in report
    long long unsigned int not_used_packets, not_used_errs, not_used_drop, not_used_fifo, not_used_frame, not_used_compressed, not_used_multicast;

    // read file content stuff
    char *line = NULL;
    size_t line_len = 0;
    ssize_t read_chars;
    uint32_t stats_array_index = 0;

    // open /proc/net/{protocol}
    FILE* fp = fopen("/proc/net/dev", "r");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fp == NULL), DS_STATUS_ERROR, "Failed to open /proc/net/dev");

    uint32_t dropped_headers = 0; 
    
    // read file content by lines and parse each line
    while ((read_chars = getline(&line, &line_len, fp)) != -1) {

        // avoid parsing of 2 first lines that contains titles
        if(dropped_headers < 2){
            dropped_headers ++;
            continue;
        }

        /*
        Inter-| Receive                                                   | Transmit                     header line
        face  | bytes    packets errs drop fifo frame compressed multicast| bytes        ...             header line
        eth2:   5788008  59755   0    0    0    0     0          0          2751000      ...
        eno1:   30035065 4850550 0    2314 0    0     0          2894166    454136946417 ...
          |     |        |       |    |    |    |     |          |           |----> transmitted bytes    reported
          |     |     not used not used  not used  not used  not used ------------>                      not reported, but required to extract
          |     |-----------------------------------------------------------------> received bytes       reported
          |-----------------------------------------------------------------------> interface name       reported

        We need to scan first 10 fileds: 'Interface',  'rx bytes', 'packets', ..., 'multicast', and 'tx bytes', 
        but only interface name and received/sent bytes reported */
        
        // extract first 10 fields
        sscanf(line, "%s %llu %llu %llu %llu %llu %llu %llu %llu %llu", if_name_field, 
          &received_bytes,                                                                                                               // received bytes
          &not_used_packets, &not_used_errs, &not_used_drop, &not_used_fifo, &not_used_frame, &not_used_compressed, &not_used_multicast, // not used fileds
          &transmit_bytes);                                                                                                              // sent bytes

        if(received_bytes == 0 && transmit_bytes == 0){
            // avoid reporting such interface
            continue;
        }

        // verify if reallocation is required
        if(stats_array_index == stats_array_current_size) {
            // reallocate the output array
            size_t new_size = sizeof(ds_stats_network_t) *(stats_array_current_size + STAT_ARRAY_BLOCK_SIZE);
            ds_stats_network_t *new_stats_array = (ds_stats_network_t *)realloc(stats_array, new_size);
            
            // in the case of allocation error, release original array in the goto label
            SA_PV_ERR_RECOVERABLE_GOTO_IF((new_stats_array == NULL), status = DS_STATUS_ERROR, release_resources,
                "Failed to reallocate memory to new size %" PRIu32 " bytes", (uint32_t)new_size);
            // stats_array original array was released, so we can just use new array
            stats_array_current_size += STAT_ARRAY_BLOCK_SIZE;
            stats_array = new_stats_array;
        }

        // cut off the colon from the interface name
        char* colon_ptr = (char*)memchr(if_name_field, ':', DS_MAX_INTERFACE_NAME_SIZE);
        // if colon not found in interface name, the format of interface name is not supported
        SA_PV_ERR_RECOVERABLE_GOTO_IF((colon_ptr == NULL), status = DS_STATUS_ERROR, release_resources,
                "Failed to find \':\' in the linux interface name");
        *colon_ptr = 0;

        // fill fields in the output array        
        strncpy(stats_array[stats_array_index].interface, if_name_field, DS_MAX_INTERFACE_NAME_SIZE);
        stats_array[stats_array_index].recv_bytes = received_bytes;
        stats_array[stats_array_index].sent_bytes = transmit_bytes;

        // on Linux we does not fill ip_addr and port
        strncpy(stats_array[stats_array_index].ip_data.ip_addr, "not valid", DS_MAX_IP_ADDR_SIZE);
        stats_array[stats_array_index].ip_data.port = NOT_USED_FIELD;


        // use only third field rem_address_field
        SA_PV_LOG_TRACE("report [%d] interface=%s, rx=%" PRIu64 ", tx=%" PRIu64, 
            stats_array_index, 
            stats_array[stats_array_index].interface, 
            stats_array[stats_array_index].recv_bytes, 
            stats_array[stats_array_index].sent_bytes);

        stats_array_index++;
    }

release_resources:
    free(line);

    if(status != DS_STATUS_SUCCESS)
    {
        free(stats_array);
        SA_PV_LOG_TRACE_FUNC_EXIT("report for interfaces was not created, status = %d", status);
        return status;
    }

    *network_stats_out = stats_array;
    *stats_count_out = stats_array_index;
    SA_PV_LOG_TRACE_FUNC_EXIT("report %" PRIu32 " interfaces", (uint32_t)stats_array_index);
    return status;
}


static ds_status_e extract_ip_addr_and_port(const char *rem_address_field, ds_stat_ip_data_t * ip_data_out)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((rem_address_field == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: rem_address_field is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data_out is NULL");
    SA_PV_LOG_TRACE_FUNC_ENTER("rem_address_field=%s", rem_address_field);

    // length of the ip address field part in the rem_address (the "AE1E320A" part in the AE1E320A:CF3D) 
    const unsigned int REM_ADDRESS_IPADDRESS_LENGTH = 8;

    // length of the ip port field part in the rem_address (the "CF3D" part in the AE1E320A:CF3D) 
    const unsigned int REM_ADDRESS_PORTNUM_LENGTH = 4;

    // index of the colon in the rem_address (the ":" in the AE1E320A:CF3D) 
    const unsigned int REM_ADDRESS_COLON_INDEX = 8;

    const unsigned int HEXA_RADIX = 16;

    size_t rem_address_field_len = strnlen(rem_address_field, DS_MAX_IP_ADDR_SIZE);

    // verify that the format is supported                    
    SA_PV_ERR_RECOVERABLE_RETURN_IF(                       // (+ 1 is for size of ":" placeholder in rem_address)
        (rem_address_field_len != REM_ADDRESS_IPADDRESS_LENGTH + 1 + REM_ADDRESS_PORTNUM_LENGTH || rem_address_field[REM_ADDRESS_COLON_INDEX] != ':'), 
        DS_STATUS_ERROR, "Wrong rem_adress(=%s)", rem_address_field);


    char *end_ptr = NULL, *end_ptr2 = NULL; // will point to next byte after the handled integer
    const uint32_t ip_addr_int = (uint32_t) strtol(rem_address_field, &end_ptr, HEXA_RADIX);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((*end_ptr != ':'), DS_STATUS_ERROR, "Ip address parsing failed, rem_adress(=%s)", rem_address_field);

    // advance end_ptr to point to the next byte after ":"
    end_ptr++;

    // end_ptr points to port number       
    //                                     not used
    ip_data_out->port = (uint16_t) strtol(end_ptr, &end_ptr2, HEXA_RADIX);

    snprintf(ip_data_out->ip_addr, DS_MAX_IP_ADDR_SIZE, "%u.%u.%u.%u", 
      ip_addr_int & 0x000000FF,                // LSB to first part of stringified ip address 
      (ip_addr_int & 0x0000FF00)>>8, 
      (ip_addr_int & 0x00FF0000)>>16, 
      (ip_addr_int & 0xFF000000)>>24);          // MSB to last part of stringified ip address
  
    SA_PV_LOG_TRACE_FUNC_EXIT("returning ip_addrs=%s port=%" PRIu16, ip_data_out->ip_addr, ip_data_out->port);
    return DS_STATUS_SUCCESS;
}


static bool avoid_report_remote_address(const char *rem_address_field, int connection_state_field, ds_net_protocol_type_t protocol)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((rem_address_field == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: rem_address_field is NULL");
    SA_PV_LOG_TRACE_FUNC_ENTER("rem_address_field=%s, connection_state_field=%d, protocol=%d", rem_address_field, connection_state_field, protocol);

    bool ret_var = false;
    // In the Internet Protocol Version 4, the address 0.0.0.0 is a non-routable meta-address used to designate an invalid, 
    // unknown or non-applicable target. These destinations should not be reported(for both, udp and tcp). 
    const char unaddressable_ip[] = "00000000";
    if (0 == strncmp(rem_address_field, unaddressable_ip, strlen(unaddressable_ip))) {
        ret_var = true;
    }

    // In the TCP Linux implementation, the only state that allows data transfer is state ESTABLISHED. 
    if(protocol == TCPV4) {
        if(connection_state_field != TCP_ESTABLISHED) {
            ret_var = true;
        }
    }

    SA_PV_LOG_TRACE_FUNC_EXIT("returning %d", ret_var);
    return ret_var;
}


static const char* protocol_to_str(ds_net_protocol_type_t protocol)
{    
    switch (protocol)
    {
    case TCPV4: return "tcp";
    case UDPV4: return "udp";
   
    default:
        SA_PV_LOG_ERR("Invalid protocol type %d", protocol);
        return "not_supported";
    };
}


static bool is_ip_addr_and_port_already_reported(const ds_stat_ip_data_t *stats_array, uint32_t number_items_to_search, const ds_stat_ip_data_t* ip_data)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data is NULL");
    SA_PV_LOG_TRACE_FUNC_ENTER("ip address=%s, port=%" PRIu16, ip_data->ip_addr, ip_data->port);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((stats_array == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: stats_array is NULL");

    bool ret_var = false;
    for (uint32_t i = 0; i <= number_items_to_search; i++) {
        if((0 == strncmp(stats_array[i].ip_addr, ip_data->ip_addr, DS_MAX_IP_ADDR_SIZE)) && 
            (stats_array[i].port == ip_data->port) ){
                ret_var = true;
                break;
            }
    }
    SA_PV_LOG_TRACE_FUNC_EXIT("returning %d", ret_var);
    return ret_var;
}

static ds_status_e ds_socket_stats_by_protocol_get(ds_stat_ip_data_t **socket_stats_out, uint32_t *dest_count_out, ds_net_protocol_type_t protocol)
{
    SA_PV_LOG_TRACE_FUNC_ENTER("protocol=%d", protocol);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((socket_stats_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: socket_stats_out is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((dest_count_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: dest_count_out is 0");

    // memory allocation stuff
    const uint32_t STAT_ARRAY_BLOCK_SIZE = 10;
    uint32_t stats_array_current_size = 0;
    ds_stat_ip_data_t *stats_array = NULL;

    // placeholders for /proc/net/{protocol} string fields
    char not_used_sl_field[128];
    char not_used_local_address_field[DS_MAX_IP_ADDR_SIZE];
    char rem_address_field[DS_MAX_IP_ADDR_SIZE];
    int connection_state_field;

    // read file content by lines stuff
    ds_status_e status = DS_STATUS_SUCCESS;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t read_chars;
    bool header_line_dropped = false;
    uint32_t stats_array_index = 0;

    const char *protocol_name = protocol_to_str(protocol);

    #define PROC_FILE_NAME_MAX_LEN 64
    char proc_file_name[PROC_FILE_NAME_MAX_LEN] = {0};
    snprintf(proc_file_name, PROC_FILE_NAME_MAX_LEN, "/proc/net/%s", protocol_name);

    // open /proc/net/{protocol}
    FILE* fp = fopen(proc_file_name, "r");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fp == NULL), DS_STATUS_ERROR, "Failed to open %s", proc_file_name);

    SA_PV_LOG_INFO("reading %s:", proc_file_name);

    // read file content by lines and parse each line
    while ((read_chars = getline(&line, &line_len, fp)) != -1) {

        // avoid parsing of first line that contains titles
        if(!header_line_dropped){
            header_line_dropped = true;
            continue;
        }

        /* /proc/net{udp or tcp} fields
          sl    local_address rem_address   st ...                          header line
          0:    00000000:006F 00000000:0000 0A 
          1:    3500007F:0035 00000000:0000 0A 
          |         |      |      |      |   |--> connection state          used for decision-making, not reported
          |         |      |      |      |------> remote TCP port number    reported
          |         |      |      |-------------> remote IPv4 address       reported
          |         |      |--------------------> local TCP port number     (not reported, but required to extract)
          |         |---------------------------> local IPv4 address        (not reported, but required to extract)
          |-------------------------------------> number of entry           (not reported, but required to extract)

          We need to scan only first 4 fileds: 'sl',  'local_address', 'rem_address' and 'st', byt only remote TCP address and port number reported */
        // extract first 4 fields
        sscanf(line, "%s %s %s %d", not_used_sl_field, not_used_local_address_field, rem_address_field, &connection_state_field);

        // use only third field rem_address_field
        SA_PV_LOG_TRACE("handling linux rem_address=%s, state=%d", rem_address_field, connection_state_field);

        // verify, may be this destination point should not be reported
        if(avoid_report_remote_address(rem_address_field, connection_state_field, protocol)){
            SA_PV_LOG_TRACE("destination address=%s, state=%d report avoided!", rem_address_field, connection_state_field);
            continue;
        }   

        // verify if reallocation is required
        if(stats_array_index == stats_array_current_size) {
            // reallocate the output array
            size_t new_size = sizeof(ds_stat_ip_data_t) *(stats_array_current_size + STAT_ARRAY_BLOCK_SIZE);
            ds_stat_ip_data_t *new_stats_array = (ds_stat_ip_data_t *)realloc(stats_array, new_size);
            
            SA_PV_ERR_RECOVERABLE_GOTO_IF((new_stats_array == NULL), status = DS_STATUS_ERROR, release_resources,
                "Failed to reallocate memory to new size %" PRIu32 " bytes", (uint32_t)new_size);

            // stats_array original array was released, so we can just use new array
            stats_array_current_size += STAT_ARRAY_BLOCK_SIZE;
            stats_array = new_stats_array;
        }

        ds_stat_ip_data_t ip_data_tmp;
        ds_status_e status = extract_ip_addr_and_port(
            rem_address_field, 
            &ip_data_tmp);

        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ERROR, release_resources,
            "Failed to extract ip addr from %s", rem_address_field);
        
        if(is_ip_addr_and_port_already_reported(stats_array, stats_array_index, &ip_data_tmp)){
            // avoid reporting this ip
            continue;
        }

        // report new ip data
        strncpy(stats_array[stats_array_index].ip_addr, ip_data_tmp.ip_addr, DS_MAX_IP_ADDR_SIZE);
        stats_array[stats_array_index].port = ip_data_tmp.port;

        SA_PV_LOG_INFO("report %s [%d]: %s:%d", 
            protocol_name, 
            stats_array_index, 
            stats_array[stats_array_index].ip_addr, 
            stats_array[stats_array_index].port);

        stats_array_index++;
    }

release_resources:

    free(line);

    if(status != DS_STATUS_SUCCESS)
    {
        free(stats_array);
        SA_PV_LOG_TRACE_FUNC_EXIT("report for %s was not created, status = %d", protocol_name, status);
        return status;
    }

    *socket_stats_out = stats_array;
    *dest_count_out = stats_array_index;
    SA_PV_LOG_TRACE_FUNC_EXIT("report %" PRIu32 " %s connections", (uint32_t)stats_array_index, protocol_name);
    return status;
}


static ds_status_e meminfo_fields_get_from_line(uint64_t *out_value, const char *exp_field_name, FILE* fp){

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    char *line = NULL; // getline will allocate line according to the required size
    size_t line_len = 0;
    ssize_t read_chars = getline(&line, &line_len, fp); // getline always puts \0 at the end
    SA_PV_ERR_RECOVERABLE_RETURN_IF((read_chars == -1), DS_STATUS_ERROR, "Failed to read content of the meminfo");
 
    /* /proc/meminfo output:
    MemTotal:       131902356 kB
    MemFree:        10437624 kB
    MemAvailable:   90474708 kB
    Buffers:         4091804 kB
    ... |               |    | 
        |               |    |----------> memory size units
        |               |---------------> memory size value in kb (reported in bytes)
        |-------------------------------> filed name (used for verifying that we read corerect filed, not reported) */

    char field_name[128] = {0};
    char size_units[128] = {0};
    long long unsigned int memory_kb = 0;
    int items_scanned = sscanf(line, "%s %llu %s", field_name, &memory_kb, size_units);
    free(line);

    // we should read exactly 3 items
    SA_PV_ERR_RECOVERABLE_RETURN_IF((items_scanned != 3), DS_STATUS_ERROR, "Failed to parse meminfo line content");

    // we should read the expected field name
    SA_PV_ERR_RECOVERABLE_RETURN_IF(strcmp(exp_field_name, field_name) != 0, DS_STATUS_ERROR, 
        "Actual field name(=%s) not as expected(=%s)", field_name, exp_field_name);

    // value read can't be 0
    SA_PV_ERR_RECOVERABLE_RETURN_IF(memory_kb == 0, DS_STATUS_ERROR, "Memory size read can't be 0");

    // units should be kb
    SA_PV_ERR_RECOVERABLE_RETURN_IF(strcmp("kB", size_units) != 0, DS_STATUS_ERROR, 
        "Actual memory size units (=%s) not as expected(=%s)", size_units, "kB");

    *out_value = (uint64_t)memory_kb;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return DS_STATUS_SUCCESS;
}


ds_status_e ds_plat_memory_stats_get(ds_stats_memory_t *mem_stats_out)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((mem_stats_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: mem_stats_out is NULL");
    
    FILE* fp = fopen("/proc/meminfo", "r");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fp == NULL), DS_STATUS_ERROR, "Failed to open /proc/meminfo");

    uint64_t mem_total_kb = 0, mem_free_kb = 0;
    ds_status_e status = meminfo_fields_get_from_line(&mem_total_kb, "MemTotal:", fp);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status, release_resources, "Failed to get MemTotal field");

    status = meminfo_fields_get_from_line(&mem_free_kb, "MemFree:", fp);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status, release_resources, "Failed to get MemFree field");

release_resources:
    fclose (fp);

    if(status == DS_STATUS_SUCCESS){

        mem_stats_out->mem_available_bytes = mem_total_kb * 1024;
        mem_stats_out->mem_used_bytes = (mem_total_kb - mem_free_kb) * 1024;

        // on Linux we collect total memory statistics
        mem_stats_out->mem_available_id = DS_METRIC_MEMORY_TOTAL;
        mem_stats_out->mem_used_id = DS_METRIC_MEMORY_USED;

        SA_PV_LOG_TRACE_FUNC_EXIT("used=%" PRIu64 ", available=%" PRIu64, mem_stats_out->mem_used_bytes, mem_stats_out->mem_available_bytes);
    }
    else {
        SA_PV_LOG_TRACE_FUNC_EXIT("failed status=%d", status);
    }

    return status;
}


ds_status_e ds_plat_active_dests_collect_and_encode(CborEncoder *main_map)
{
    CborEncoder active_dests_array;
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((main_map == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: main_map is NULL");

    // encode active destinations
    CborError cbor_err = cbor_encode_uint(main_map, DS_METRIC_ACTIVE_DESTS);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode active dests key");

    // we don't know how much metrics will be, so put CborIndefiniteLength
    cbor_err = cbor_encoder_create_array(main_map, &active_dests_array, CborIndefiniteLength);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create active dests array");

    // fetch all active destinations

    // go over all active destinations and encode them to array
    ds_stat_ip_data_t *tcp_ip_stat_array = NULL, *udp_ip_stat_array = NULL;
    uint32_t tcp_stat_count = 0, udp_stat_count = 0;

    // get TCP data
    ds_status_e status = ds_socket_stats_by_protocol_get(&tcp_ip_stat_array, &tcp_stat_count, TCPV4);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to get tcp stats");

    // encode TCP data if exists
    if(tcp_ip_stat_array != NULL){
        status = ds_ip_data_array_encode(tcp_ip_stat_array, tcp_stat_count, &active_dests_array);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode tcp stats");
    }

    // free tcp_ip_stat_array to minimize memory maximal consumption
    free(tcp_ip_stat_array);
    tcp_ip_stat_array = NULL;

    // get UDP data
    status = ds_socket_stats_by_protocol_get(&udp_ip_stat_array, &udp_stat_count, UDPV4);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to get udp stats");

    // encode UDP data if exists
    if(udp_ip_stat_array != NULL){
        status = ds_ip_data_array_encode(udp_ip_stat_array, udp_stat_count, &active_dests_array);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode udp stats");
    }

    // close active_dests_array
    cbor_err = cbor_encoder_close_container(main_map, &active_dests_array);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to close active dests array");

release_resources:
    // free resources in any case, it's ok to pass NULL to free()
    free(tcp_ip_stat_array);
    free(udp_ip_stat_array);

    if(status != DS_STATUS_SUCCESS){
        SA_PV_LOG_TRACE_FUNC_EXIT("failed with error %d", status);
    }
    else {
        SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    }
    return status;
}


ds_status_e ds_plat_labeled_metric_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data)
{
    (void)ip_data_map;
    (void)ip_data;
    // ip data active network metrics not relevant for Linux OS - do nothing
    return DS_STATUS_SUCCESS;
}
