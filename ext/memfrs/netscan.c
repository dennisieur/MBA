/*
 *  MBA Network scanning Introspection Implementation
 *
 *  Copyright (c)   2016 ELin Ho
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu-common.h"
#include "exec/cpu-all.h"

#include "memfrs.h"
#include "memfrs-priv.h"
#include<stdlib.h>
#include<time.h>

#include "netscan.h"

#define SIZE_OF_POOL_HEADER 0x10
#define MAX_IMAGENAME_SIZE 16
#define MAX_IP_PORT_SIZE 46
#define TIME_SIZE 26


// Convert port from Big Endian to Little Endian.
// type : uint16_t to int
#define port_convert(port) ((port%0x100)*256 + (port >> 8))


/*********************************************************************************
/// mapping TCP state from state number to state string
///
/// \param state        state number
///
/// return a pointer to state string
**********************************************************************************/
static const char* map_state_to_str(uint32_t state)
{
    switch (state) {
        case TCP_CLOSED:  return "CLOSED"; break;
        case TCP_LISTENING:  return "LISTENING"; break;
        case TCP_SYN_SENT:  return "SYN_SENT"; break;
        case TCP_SYN_RCVD:  return "SYN_RCVD"; break;
        case TCP_ESTABLISHED:  return "ESTABLISHED"; break;
        case TCP_FIN_WAIT1:  return "FIN_WAIT1";  break;
        case TCP_FIN_WAIT2:  return "FIN_WAIT2";  break;
        case TCP_CLOSE_WAIT:  return "CLOSE_WAIT"; break;
        case TCP_CLOSING:  return "CLOSING";  break;
        case TCP_LAST_ACK:  return "LAST_ACK";  break;
        case TCP_TIME_WAIT: return "TIME_WAIT";  break;
        case TCP_DELETE_TCP: return "DELETE_TCP";  break;
        default: return "UNKOWN"; break;
    }
    return "UNKOWN";
}



/*********************************************************************************
/// Add a network data in UT_array structure network_state
///
/// protocol        network protocol, including UDP/TCP and IPv4/IPv6
/// pmem            physical memory address of the pool tag address
/// eprocess        eprocess address in virtual memoey
/// imagename       the image file name of owner process
/// pid             the process id of owner process
/// state           TCP connect state
/// local_addr      local address
/// foreign_addr    foreign address
/// time            windows timestamp
/// network_list    target network_state structure
///
/// return nothing
**********************************************************************************/
static void add_network_feild_to_structure(
        const char* protocol,
        uint64_t pmem,
        uint64_t eprocess,
        uint8_t* imagename,
        uint64_t pid,
        const char* state,
        char* local_addr,
        char* foreign_addr,
        char* time,
        UT_array *network_list)
{
    network_state network_data;

    // protocol
    network_data.protocol = protocol;

    // pgysical memory
    network_data.pmem = pmem;

    // eprocess
    network_data.eprocess = eprocess;

    // image file name
    snprintf(network_data.imagename, MAX_IMAGENAME_SIZE, "%s", imagename);

    // process id
    network_data.pid = pid;

    // state of Tcp Endpoint
    network_data.state = state ? state : calloc(1, sizeof(char));

    // local address
    snprintf(network_data.local_addr, MAX_IP_PORT_SIZE, "%s", local_addr);

    // foreign address
    snprintf(network_data.foreign_addr, MAX_IP_PORT_SIZE, "%s", foreign_addr);

    // createtime
    snprintf(network_data.time, TIME_SIZE-1, "%s", time);
    network_data.time[TIME_SIZE-1] = '\0';

    utarray_push_back(network_list, &network_data);
}



/*********************************************************************************
/// Convert windows time to timestamp
///
/// \param port     windows time
///
/// return a pointer to char array, stored timestamp
**********************************************************************************/
static char* windows_timestamp_convert(uint64_t time)
{
    double second;
    time_t windows_time;

    // convert time to seconds
    second = time/10000000.0;

    // # Convert NTP time to Windows time
    // ntp time begin from 1601 but Windows time begin from 1970
    // 11644473600 is number of seconds from 1601 to 1970
    windows_time = second-11644473600;

    // convert seconds to timestamp
    return ctime(&windows_time);
}



/*********************************************************************************
/// Parse IPv6 data from virtual address
///
/// \param addr_ptr     an virtual memory address of IPv4 address 
/// \param port         port in Big Endian type
/// \param cpu          pointer to current cpu
///
/// return a pointer to char array, stored IPv4 string
**********************************************************************************/
static int IPv6_to_str(char *addr, uint64_t addr_ptr, uint16_t port, CPUState *cpu)
{
    uint64_t i;
    uint8_t addr_v6;

    // the ipv6 address stored in virtual memory is 2*8 bytes
    for (i=0 ; i<0x10 ; ++i) {
        // the ipv6 address stored in virtual memory is spilited by 2 bytes
        if (cpu_memory_rw_debug(cpu, addr_ptr+i, (uint8_t*)&addr_v6, 2, 0) != 0)
            return -1;
        if (i%2 == 0)
            snprintf(addr+strlen(addr), MAX_IP_PORT_SIZE-strlen(addr), "%"PRIx16, addr_v6);
        else
            snprintf(addr+strlen(addr), MAX_IP_PORT_SIZE-strlen(addr), "%"PRIx16":", addr_v6);
    }

    snprintf(addr+strlen(addr), MAX_IP_PORT_SIZE-strlen(addr), "%d", port_convert(port));
    return 0;
}



/*********************************************************************************
/// Parse IPv4 data from virtual address
///
/// \param addr_ptr     an virtual memory address of IPv4 address 
/// \param port         port in Big Endian type
/// \param cpu          pointer to current cpu
///
/// return a pointer to char array, stored IPv4 string
**********************************************************************************/
static int IPv4_to_str(char *addr, uint64_t addr_ptr, uint16_t port, CPUState *cpu)
{
    int i;
    uint32_t addr_v4;

    // the ipv4 address stored in virtual memory is 4 bytes
    if (cpu_memory_rw_debug(cpu, addr_ptr, (uint8_t*)&addr_v4, 4, 0) != 0)
        return -1;
    for (i=0 ; i<4 ; ++i) {
        snprintf(addr+strlen(addr), MAX_IP_PORT_SIZE-strlen(addr), "%d.", addr_v4%256);
        addr_v4 = addr_v4>>8;
    }

    addr[strlen(addr)-1]=':';
    snprintf(addr+strlen(addr), MAX_IP_PORT_SIZE-strlen(addr), "%d", port_convert(port));

    return 0;
}



/*********************************************************************************
/// Parse the whole Tcp Listening datas if found pool tag "TcpL" in physical memory
///
/// \param offset_tag       offset from pool header to pool tag
/// \param pmem             physical address
/// \param network_list     pointer to network list, its a UT_array of structure "networt_state"
/// \param cpu              pointer to current cpu
///
/// return nothing
**********************************************************************************/
static void parse_TcpL(uint64_t pool_body_ptr, uint64_t pmem, UT_array *network_list, CPUState *cpu)
{
    uint64_t addr1,
             addr2;

    uint8_t AF;
    uint16_t port_local;
    uint64_t eprocess_ptr,
             processid,
             time;
    char addr[MAX_IP_PORT_SIZE] = {0},
         addr_foreign[MAX_IP_PORT_SIZE] = {0};
    uint8_t imagename[MAX_IMAGENAME_SIZE];

    // InetAF
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&AF, sizeof(AF), pool_body_ptr, true, "_TCP_LISTENER", 2, "*InetAF", "#AddressFamily") != 0)
        return;

    // Owner
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), pool_body_ptr, true, "_TCP_LISTENER", 1, "*Owner") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&processid, sizeof(processid), eprocess_ptr, false, "_EPROCESS", 1, "#UniqueProcessId") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)imagename, sizeof(imagename), eprocess_ptr, false, "_EPROCESS", 1, "#ImageFileName") != 0)
        return;
    imagename[MAX_IMAGENAME_SIZE-1] = '\0';

    // CreateTime
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&time, sizeof(time), pool_body_ptr, true, "_TCP_LISTENER", 1, "#CreateTime") != 0)
        return;

    // Local port
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&port_local, sizeof(port_local), pool_body_ptr, true, "_TCP_LISTENER", 1, "#Port") != 0)
        return;


    // is_valid
    if (eprocess_ptr<0xffff000000000000 || processid==0 || processid>65535 || port_local==0)
        return;


    // Address
    if (AF == AF_INET) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_LISTENER", 1, "*LocalAddr") != 0)
            return;
        else if (addr1 == 0x0000000000000000)
            snprintf(addr, MAX_IP_PORT_SIZE, "0.0.0.0:%d", port_convert(port_local));
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr2, sizeof(addr2), addr1, false, "_LOCAL_ADDRESS", 1, "*pData") != 0)
            return;
        // 0x28 is a magic number for the offset from ip address to pData
        else if (IPv4_to_str(addr, addr2+0x28, port_local, cpu) == -1)
            return;

        // Foreign address
        snprintf(addr_foreign, MAX_IP_PORT_SIZE, "0.0.0.0:0");

        add_network_feild_to_structure("TCPv4", pmem, eprocess_ptr, imagename, processid, "LISTENING", addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else if (AF == AF_INET6) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_LISTENER", 1, "*LocalAddr") != 0)
            return;
        else if (addr1 == 0x0000000000000000)
            snprintf(addr, MAX_IP_PORT_SIZE, "0.0.0.0.0.0.0.0:%d", port_convert(port_local));
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr2, sizeof(addr2), addr1, false, "_LOCAL_ADDRESS", 1, "*pData") != 0)
            return;
        // 0x28 is a magic number for the offset from ip address to pData
        else if (IPv6_to_str(addr, addr2+0x28, port_local, cpu) == -1)
                return;

        // Foreign address
        snprintf(addr_foreign, MAX_IP_PORT_SIZE, "0.0.0.0:0");

        add_network_feild_to_structure("TCPv6", pmem, eprocess_ptr, imagename, processid, "LISTENING", addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else{
        return;
    }
}



/*********************************************************************************
/// Parse the whole Tcp Endpoint datas if found pool tag "TcpE" in physical memory
///
/// \param offset_tag       offset from pool header to pool tag
/// \param pmem             physical address
/// \param network_list     pointer to network list, its a UT_array of structure "networt_state"
/// \param cpu              pointer to current cpu
///
/// return nothing
**********************************************************************************/
static void parse_TcpE(uint64_t pool_body_ptr, uint64_t pmem, UT_array *network_list, CPUState *cpu)
{
    uint64_t addr1;

    uint8_t AF;
    uint32_t state;
    uint16_t port_local,
             port_foreign;
    uint64_t eprocess_ptr,
             processid,
             time;
    char addr[MAX_IP_PORT_SIZE] = {0},
         addr_foreign[MAX_IP_PORT_SIZE] = {0};
    const char* state_str;
    uint8_t imagename[MAX_IMAGENAME_SIZE];

    int offset_local_addr4_to_INADDR,
        offset_local_addr6_to_INADDR,
        offset_remote_addr4_to_INADDR,
        offset_remote_addr6_to_INADDR;

    memfrs_get_nested_field_offset(&offset_local_addr4_to_INADDR, "_IN_ADDR_WIN10_TCPE", 1, "addr4");
    memfrs_get_nested_field_offset(&offset_local_addr6_to_INADDR, "_IN_ADDR_WIN10_TCPE", 1, "addr6");
    memfrs_get_nested_field_offset(&offset_remote_addr4_to_INADDR, "_IN_ADDR", 1, "addr4");
    memfrs_get_nested_field_offset(&offset_remote_addr6_to_INADDR, "_IN_ADDR", 1, "addr6");

    // InetAF
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&AF, sizeof(AF), pool_body_ptr, true, "_TCP_ENDPOINT", 2, "*InetAF", "#AddressFamily") != 0)
        return;

    // Owner
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), pool_body_ptr, true, "_TCP_ENDPOINT", 1, "*Owner") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&processid, sizeof(processid), eprocess_ptr, false, "_EPROCESS", 1, "#UniqueProcessId") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)imagename, sizeof(imagename), eprocess_ptr, false, "_EPROCESS", 1, "#ImageFileName") != 0)
        return;
    imagename[MAX_IMAGENAME_SIZE-1] = '\0';

    // CreateTime
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&time, sizeof(time), pool_body_ptr, true, "_TCP_ENDPOINT", 1, "#CreateTime") != 0)
        return;

    // Local port
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&port_local, sizeof(port_local), pool_body_ptr, true, "_TCP_ENDPOINT", 1, "#LocalPort") != 0)
        return;

    // Local foreign
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&port_foreign, sizeof(port_foreign), pool_body_ptr, true, "_TCP_ENDPOINT", 1, "#RemotePort") != 0)
        return;

    // state
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&state, sizeof(state), pool_body_ptr, true, "_TCP_ENDPOINT", 1, "#State") != 0)
        return;
    state_str = map_state_to_str(state);


    // is_valid
    if (eprocess_ptr<=0xffff000000000000 || processid==0 || processid>65535 || port_local==0 || port_foreign==0)
        return;


    // Address
    if (AF == AF_INET) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_ENDPOINT", 3, "*AddrInfo", "*Local", "*pData") != 0)
            return;
        else if (IPv4_to_str(addr, addr1+ offset_local_addr4_to_INADDR, port_local, cpu) == -1)
            return;

        // Foreign address
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_ENDPOINT", 2, "*AddrInfo", "*Remote") != 0)
            return;
        else if (IPv4_to_str(addr_foreign, addr1+ offset_remote_addr4_to_INADDR, port_foreign, cpu) == -1)
            return;

        add_network_feild_to_structure("TCPv4", pmem, eprocess_ptr, imagename, processid, state_str, addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else if (AF == AF_INET6) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_ENDPOINT", 3, "*AddrInfo", "*Local", "*pData") != 0)
            return;
        else if (IPv6_to_str(addr, addr1+ offset_local_addr6_to_INADDR, port_local, cpu) == -1)
            return;

        // Foreign address
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_TCP_ENDPOINT", 2, "*AddrInfo", "*Remote") != 0)
            return;
        else if (IPv6_to_str(addr_foreign, addr1+ offset_remote_addr6_to_INADDR, port_foreign, cpu) == -1)
            return;

        add_network_feild_to_structure("TCPv6", pmem, eprocess_ptr, imagename, processid, state_str, addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else {
        return;
    }
}



/*********************************************************************************
/// Parse the whole Udp datas if found pool tag "UdpA" in physical memory
///
/// \param offset_tag       offset from pool header to pool tag
/// \param pmem             physical address
/// \param network_list     pointer to network list, its a UT_array of structure "networt_state"
/// \param cpu              pointer to current cpu
///
/// return nothing
**********************************************************************************/
static void parse_UdpA(uint64_t pool_body_ptr, uint64_t pmem, UT_array *network_list, CPUState *cpu)
{
    uint64_t addr1, addr2;

    uint8_t AF;
    uint16_t port_local;
    uint64_t eprocess_ptr,
             processid,
             time;
    char addr[MAX_IP_PORT_SIZE] = {0},
         addr_foreign[MAX_IP_PORT_SIZE] = {0};
    uint8_t imagename[MAX_IMAGENAME_SIZE];

    // InetAF
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&AF, sizeof(AF), pool_body_ptr, true, "_UDP_ENDPOINT", 2, "*InetAF", "#AddressFamily") != 0)
        return;

    // Owner
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), pool_body_ptr, true, "_UDP_ENDPOINT", 1, "*Owner") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&processid, sizeof(processid), eprocess_ptr, false, "_EPROCESS", 1, "#UniqueProcessId") != 0)
        return;
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)imagename, sizeof(imagename), eprocess_ptr, false, "_EPROCESS", 1, "#ImageFileName") != 0)
        return;
    imagename[MAX_IMAGENAME_SIZE-1] = '\0';

    // CreateTime
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&time, sizeof(time), pool_body_ptr, true, "_UDP_ENDPOINT", 1, "#CreateTime") != 0)
        return;

    // Local port
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&port_local, sizeof(port_local), pool_body_ptr, true, "_UDP_ENDPOINT", 1, "#Port") != 0)
        return;


    // is_valid
    if (eprocess_ptr<0xffff000000000000 || processid==0 || processid>65535 || port_local==0)
        return;


    // Address
    if (AF == AF_INET) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_UDP_ENDPOINT", 1, "*LocalAddr") != 0)
            return;
        else if (addr1 == 0x0000000000000000)
            snprintf(addr, MAX_IP_PORT_SIZE, "0.0.0.0:%d", port_convert(port_local));
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr2, sizeof(addr2), addr1, false, "_LOCAL_ADDRESS_WIN10_UDP", 1, "*pData") != 0)
            return;
        else if (IPv4_to_str(addr, addr2, port_local, cpu) == -1)
            return;

        // Foreign address
        snprintf(addr_foreign, MAX_IP_PORT_SIZE, "*:*");

        add_network_feild_to_structure("UDPv4", pmem, eprocess_ptr, imagename, processid, NULL, addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else if (AF == AF_INET6) {
        // Local address
        if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr1, sizeof(addr1), pool_body_ptr, true, "_UDP_ENDPOINT", 1, "*LocalAddr") != 0)
            return;
        else if (addr1 == 0x0000000000000000)
            snprintf(addr, MAX_IP_PORT_SIZE, "0.0.0.0.0.0.0.0:%d", port_convert(port_local));
        else if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr2, sizeof(addr2), addr1, false, "_LOCAL_ADDRESS_WIN10_UDP", 1, "*pData") != 0)
            return;
        else if (IPv6_to_str(addr, addr2, port_local, cpu) == -1)
            return;

        // Foreign address
        snprintf(addr_foreign, MAX_IP_PORT_SIZE, "*:*");

        add_network_feild_to_structure("UDPv6", pmem, eprocess_ptr, imagename, processid, NULL, addr, addr_foreign, windows_timestamp_convert(time), network_list);
    }
    else {
        return;
    }
}



UT_icd network_icd = {sizeof(network_state), NULL, NULL, NULL};


extern UT_array* memfrs_scan_network(CPUState *cpu)
{
    UT_array *network_list = NULL;

    uint64_t pmem,
             pool_body_ptr;
    uint8_t* pool_tag;
    size_t length_pool_tag;
    int offset_tag;
    json_object *test_obj;


    // Size of pool tag "UdpA", "TcpL", "TcpE" is the same
    length_pool_tag = strlen(POOL_TAG_UDP_ENDPOINT);
    //length_pool_tag = strlen(POOL_TAG_TCP_ENDPOINT);
    //length_pool_tag = strlen(POOL_TAG_TCP_LISTENER);
    pool_tag = (uint8_t*)malloc(length_pool_tag);


    // Check if network ds metadata is already loaded
    json_object_object_get_ex(g_struct_info, "_TCP_LISTENER", &test_obj);
    if (test_obj == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_NETWORK_STRUCTURE;
        free(pool_tag);
        return NULL;
    }
    json_object_object_get_ex(g_struct_info, "_TCP_ENDPOINT", &test_obj);
    if (test_obj == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_NETWORK_STRUCTURE;
        free(pool_tag);
        return NULL;
    }
    json_object_object_get_ex(g_struct_info, "_UDP_ENDPOINT", &test_obj);
    if (test_obj == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_NETWORK_STRUCTURE;
        free(pool_tag);
        return NULL;
    }
    // Check if the data structure information is already loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        free(pool_tag);
        return NULL;
    }
    else{
        memfrs_get_nested_field_offset(&offset_tag, "_POOL_HEADER", 1, "PoolTag");
    }


    utarray_new(network_list, &network_icd);


    //Scan whole physical memory
    for (pmem = 0 ; pmem < MAXMEM-length_pool_tag ; ++pmem) {
        //if(pmem%0x10000000==0x0)
            //printf("Scan physical address: 0x%"PRIx64"\n", pmem);

        // Read tag
        cpu_physical_memory_read(pmem, pool_tag, length_pool_tag);

        // pool body address
        pool_body_ptr = pmem- offset_tag+ SIZE_OF_POOL_HEADER;

        // UdpA (UDP Endpoint)
        if (memcmp(pool_tag, POOL_TAG_UDP_ENDPOINT, length_pool_tag) == 0)
            parse_UdpA(pool_body_ptr, pmem-offset_tag, network_list, cpu);
        // TCP EndPoint
        else if (memcmp(pool_tag, POOL_TAG_TCP_ENDPOINT, length_pool_tag) == 0)
            parse_TcpE(pool_body_ptr, pmem-offset_tag, network_list, cpu);
        // TCP Listening
        else if (memcmp(pool_tag, POOL_TAG_TCP_LISTENER, length_pool_tag) == 0)
            parse_TcpL(pool_body_ptr, pmem-offset_tag, network_list, cpu);
        else
            continue;
    }

    free(pool_tag);
    return network_list;
}
