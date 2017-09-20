/*
 *  MBA Virtual Machine Memory Introspection implementation
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
#include "include/utarray.h"
#include "include/uthash.h"
#include "json-c/json.h"

#include "memfrs.h"
#include "memfrs-priv.h"
#include "handles.h"
#include<stdlib.h>

#define _OBJECT_HEADER_CREATOR_INFO 0x20
#define _OBJECT_HEADER_NAME_INFO 0x20
#define _OBJECT_HEADER_HANDLE_INFO 0x10
#define _OBJECT_HEADER_QUOTA_INFO 0x20
#define _OBJECT_HEADER_PROCESS_INFO 0x10
#define _OBJECT_HEADER_AUDIT_INFO 0x10
#define _OBJECT_HEADER_PADDING_INFO 0x4

#define GRANTED_ACCESS_MASK 0x0000000001ffffff
#define TABLE_LEVEL_MASK 0x3
#define TABLE_CODE_MASK 0xfffffffffffffffc

#define MAX_IMAGENAME_SIZE 16
#define MAX_HANDLE_NUMBER 0x1000
#define MAX_POINTER_NUMBER 0x1000000

static int g_body_to_object_header;



/*******************************************************************
/// add a handle entry data in UT_array structure process
/// 
/// \param handle_node              target handles_node structure
/// \param entry_index              entry table index
/// \param handle_table_entry_ptr   address of handle table entey 
/// \param granted_access           granted access
/// \param true_type                true type of handle table entry
/// \param detail                   details of handles table entry
///
/// no return value
*******************************************************************/
static void add_handle_field_to_struct(UT_array *handle_node, int entry_index, uint64_t handle_table_entry_ptr, uint64_t granted_access, char *true_type, char *detail)
{
    handles_node_st handle_node_data;

    // entry_index
    handle_node_data.handle_table_entry_index = entry_index;

    // handle_table_entry_ptr
    handle_node_data.handle_table_entry_address = handle_table_entry_ptr;

    // granted_access
    handle_node_data.granted_access = granted_access;

    // true_typr
    handle_node_data.type = true_type;

    // detail 
    handle_node_data.detail = detail ? detail : calloc(1, sizeof(char));

    utarray_push_back(handle_node, &handle_node_data);
}



/*******************************************************************
/// extract handle table name info detail from handle_table_entry_name_info of handle table entry
///
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return the string of name info detail
*******************************************************************/
static char* extract_entry_name_info_detail(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    uint64_t object_header_name_info_ptr;
    uint8_t infomask;
    char *name_info_detail = NULL;

    int offset_name_to_object_header_name_info = 0;

    // Get Name offset from _OBJECT_HEADER_NAME_INFO
    memfrs_get_nested_field_offset(&offset_name_to_object_header_name_info, "_OBJECT_HEADER_NAME_INFO", 1, "Name");

    memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&infomask, sizeof(infomask), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#InfoMask");
    // # This specifies the order the headers are found below the _OBJECT_HEADER
    // optional_header_mask = (
    //     ('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
    //     ('NameInfo',    '_OBJECT_HEADER_NAME_INFO',    0x02),
    //     ('HandleInfo',  '_OBJECT_HEADER_HANDLE_INFO',  0x04),
    //     ('QuotaInfo',   '_OBJECT_HEADER_QUOTA_INFO',   0x08),
    //     ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
    //     ('AuditInfo',   '_OBJECT_HEADER_AUDIT_INFO',   0x20),
    //     ('PaddingInfo', '_OBJECT_HEADER_PADDING_INFO', 0x40)
    // )
    //
    // we need to check if there is a structure before _OBJECT_HEADER_NAME_INFO or not, so we need to check the infomask.
    // if infomask & 0x2 is true, there is a _OBJECT_HEADER_NAME_INFO.
    // if infomask & 0x1 is true, there is a _OBJECT_HEADER_CREATOR_INFO.
    if (infomask & 0x2) {
        if (infomask & 0x1)
            object_header_name_info_ptr = handle_table_entry_ptr - _OBJECT_HEADER_CREATOR_INFO - _OBJECT_HEADER_NAME_INFO;
        else
            object_header_name_info_ptr = handle_table_entry_ptr - _OBJECT_HEADER_NAME_INFO;

        name_info_detail = parse_unicode_strptr(object_header_name_info_ptr + offset_name_to_object_header_name_info, cr3, cpu);
    }

    return name_info_detail;
}



/*******************************************************************
/// extract registry detail from handle table entry
///
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return the string of process detail
*******************************************************************/
static char* extract_process_detail(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    uint64_t handle_table_entry_body_ptr;
    uint64_t pid;
    char *process_detail = NULL;
    uint8_t imagename[16];

    handle_table_entry_body_ptr = handle_table_entry_ptr+g_body_to_object_header;
    memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)imagename, sizeof(imagename), handle_table_entry_body_ptr, false, "_EPROCESS", 1, "#ImageFileName");
    memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&pid, sizeof(pid), handle_table_entry_body_ptr, false, "_EPROCESS", 1, "#UniqueProcessId");

    // process detail length may not greater than 32
    process_detail = (char *)malloc(32);
    memset(process_detail, 0, 32);
    snprintf(process_detail, 32, "{%s}({%"PRIx64"})", imagename, pid);

    return process_detail;
}



/*******************************************************************
/// extract registry detail from handle table entry
///
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return the string of registry detail
*******************************************************************/
static char* extract_registry_detail(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    char *tmp_registry_detail = NULL,
         *registry_detail = NULL;

    uint64_t handle_table_entry_body_ptr, 
             kcb_ptr,
             kcb_parent_ptr;
    uint16_t key_length,
             total_key_length = 0,
             tmp_key_length = 0;

    // [XXX] registry name
    // +0x01a Name to 0x20 : [1] Wchar
    // Need to check the size
    uint8_t name[256];

    handle_table_entry_body_ptr = handle_table_entry_ptr+g_body_to_object_header;
    memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&kcb_ptr, sizeof(kcb_ptr), handle_table_entry_body_ptr, false, "_CM_KEY_BODY", 1, "*KeyControlBlock");

    while (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&kcb_parent_ptr, sizeof(kcb_parent_ptr), kcb_ptr, false, "_CM_KEY_CONTROL_BLOCK", 1, "*ParentKcb") != -1) {

        memset(name, 0, 256);
        if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&name, sizeof(name), kcb_ptr, false, "_CM_KEY_CONTROL_BLOCK", 2, "*NameBlock", "#Name") == -1)
            break;

        memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&key_length, sizeof(key_length), kcb_ptr, false, "_CM_KEY_CONTROL_BLOCK", 2, "*NameBlock", "#NameLength");

        total_key_length = total_key_length + key_length + 1;

        if (tmp_registry_detail)
            free(tmp_registry_detail);
        tmp_registry_detail = registry_detail;
        registry_detail = (char*)malloc(total_key_length);

        snprintf(registry_detail, key_length+1, "%s", name);

        // every level of registry key name is splited by '\'
        if (tmp_registry_detail)
            snprintf(registry_detail+key_length, tmp_key_length, "\\%s", tmp_registry_detail);

        tmp_key_length = total_key_length;

        kcb_ptr = kcb_parent_ptr;
    }

    if (total_key_length>0) {
        registry_detail[total_key_length-1] = '\0';
        return registry_detail;
    }
    else
        return NULL;
}



/*******************************************************************
/// extract thread detail from handle table entry
/// 
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return the string of thread detail
*******************************************************************/
static char* extract_thread_detail(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    uint64_t handle_table_entry_body_ptr;
    unsigned int pid,
                 tid;
    char *thread_detail = NULL;

    handle_table_entry_body_ptr = handle_table_entry_ptr+g_body_to_object_header;
    if (
       (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&pid, sizeof(pid), handle_table_entry_body_ptr, false, "_ETHREAD", 2, "#Cid", "#UniqueProcess") != -1)
    && (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&tid, sizeof(tid), handle_table_entry_body_ptr, false, "_ETHREAD", 2, "#Cid", "#UniqueThread") != -1)
    ) {
        // thread detail length may not greater than 32
        thread_detail = (char*)malloc(32);
        memset(thread_detail, 0, 32);
        snprintf(thread_detail, 32, "{TID %d PID %d}", pid, tid);
    }

    return thread_detail;
}



/*******************************************************************
/// extract file detail from handle table entry
/// 
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return the string of file detail
*******************************************************************/
static char* extract_file_detail(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    uint64_t handle_table_entry_body_ptr,
             device_entry_body_ptr;
    uint8_t device_infomask;
    char *device_detail = NULL,
         *file_detail = NULL,
         *device_file_detail = NULL;
    uint16_t max_file_length = 0;

    int offset_filename_to_file_object = 0;

    // Get FileName offset from _FILE_OBJECT
    memfrs_get_nested_field_offset(&offset_filename_to_file_object, "_FILE_OBJECT", 1, "FileName");


    // Check and extract device path info
    handle_table_entry_body_ptr = handle_table_entry_ptr + g_body_to_object_header;
    memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&device_entry_body_ptr, sizeof(device_entry_body_ptr), handle_table_entry_body_ptr, false, "_DEVICE_OBJECT", 1, "*DriverObject");
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&device_infomask, sizeof(device_infomask), device_entry_body_ptr-g_body_to_object_header, false, "_OBJECT_HEADER", 1, "#InfoMask") != -1)
        device_detail = extract_entry_name_info_detail(device_entry_body_ptr - g_body_to_object_header, cr3, cpu);

    file_detail = parse_unicode_strptr(handle_table_entry_body_ptr + offset_filename_to_file_object, cr3, cpu);

    if (device_detail != NULL) {

        if (file_detail != NULL) {
            // "\Device\" length is 8, and end of string is 1
            max_file_length = 8+strlen(device_detail)+strlen(file_detail);
            device_file_detail = (char*)malloc(max_file_length);
            memset(device_file_detail, 0, max_file_length);
            snprintf(device_file_detail, max_file_length, "\\Device\\%s%s", device_detail, file_detail);
        }
        else {
            // "\Device\" length is 8, and end of string is 1
            max_file_length = 8+strlen(device_detail);
            device_file_detail = (char*)malloc(max_file_length);
            memset(device_file_detail, 0, max_file_length);
            snprintf(device_file_detail, max_file_length, "\\Device\\%s", device_detail);
        }

        return device_file_detail;
    }
    else if (file_detail != NULL)
        return file_detail;

    return NULL;
}



/*******************************************************************
/// extract data of handle
/// 
/// \param entry_index              the index of level 0
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param granted_access           the granted access of handle
/// \param cr3                      the current cr3
/// \param process                  the UT_array structure with handles data of one process
/// \param cpu                      the pointer to current cpu
///
/// no return value
*******************************************************************/
static void do_table_entry(int entry_index, uint64_t handle_table_entry_ptr, uint64_t granted_access, uint64_t cr3, UT_array *process, CPUState *cpu)
{
    uint64_t object_type_ptr;
    uint8_t cookie,
            type_index,
            true_type_index;
    char *true_type_name,
         *detail = NULL;

    uint64_t nt_kernel_base = 0,
             global_ObTypeIndexTable_ptr,
             global_ObHeaderCookie_ptr;
    json_object *gvar = NULL;
    int offset_name_to_object_type = 0;

    // Get Name offset from _OBJECT_TYPE
    memfrs_get_nested_field_offset(&offset_name_to_object_type, "_OBJECT_TYPE", 1, "Name"); 


    // Get global variable "ObTypeIndexTable" address 
    nt_kernel_base = memfrs_get_nt_kernel_base();
    if (nt_kernel_base == 0)
        nt_kernel_base = memfrs_find_nt_kernel_base(cpu);
    gvar = memfrs_q_globalvar("ObTypeIndexTable");
    global_ObTypeIndexTable_ptr = memfrs_gvar_offset(gvar) + nt_kernel_base;

    // # In Windows 10 the type index is obfuscated
    // Windows 10 obfuscates the object type using a cookie:
    // 
    // ------ nt!ObpRemoveObjectRoutine ------: reversing
    // Cookie stored in global variable ObHeaderCookie
    //
    // Get global variable "ObHeaderCookie" value
    gvar = memfrs_q_globalvar("ObHeaderCookie");
    global_ObHeaderCookie_ptr = memfrs_gvar_offset(gvar) + nt_kernel_base;
    cpu_memory_rw_debug(cpu, global_ObHeaderCookie_ptr, (uint8_t*)&cookie, sizeof(cookie), 0);


    // Handle table entry format in Windows10
    // Unlocked        : Bitfield Pos 0, 1 Bit
    // RefCnt          : Bitfield Pos 1, 16 Bit
    // Attributes      : Bitfield Pos 17, 3 Bit
    // ObjectPointerBits : Bitfield Pos 20, 44 Bit
    // GrantedAccessBits : Bitfield Pos 0, 25 Bit
    // NoRightsUpgrade : Bitfield Pos 25, 1 Bit
    // Spare1          : Bitfield Pos 26, 6 Bit
    // Spare2          : Uint4B
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&type_index, sizeof(type_index), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#TypeIndex") != -1){
        true_type_index = (uint8_t)((type_index ^ cookie ^ ((handle_table_entry_ptr & 0x0000ffffffffffff)>>8))& 0xff );

        cpu_memory_rw_debug( cpu, global_ObTypeIndexTable_ptr + 0x8*true_type_index, (uint8_t*)&object_type_ptr, sizeof(object_type_ptr), 0);
        true_type_name = parse_unicode_strptr(object_type_ptr+offset_name_to_object_type, cr3, cpu);

        if (strcmp(true_type_name, "File") == 0)
            detail = extract_file_detail(handle_table_entry_ptr, cr3, cpu);

        else if (strcmp(true_type_name, "Thread") == 0)
            detail = extract_thread_detail(handle_table_entry_ptr, cr3, cpu);

        else if (strcmp(true_type_name, "Key") == 0)
            detail = extract_registry_detail(handle_table_entry_ptr, cr3, cpu);

        else if (strcmp(true_type_name, "Process") == 0)
            detail = extract_process_detail(handle_table_entry_ptr, cr3, cpu);

        else
            detail = extract_entry_name_info_detail(handle_table_entry_ptr, cr3, cpu);


        add_handle_field_to_struct(process, entry_index*4, handle_table_entry_ptr, granted_access, true_type_name, detail);
    }
}



/*******************************************************************
/// check whether handle table entry is legal
///
/// \param handle_table_entrt_ptr   the address of handle table entry
/// \param cr3                      the current cr3
/// \param cpu                      the pointer to current cpu
///
/// return 1 if entry is legal, return 0 if illegal
*******************************************************************/
static int entry_is_legal(uint64_t handle_table_entry_ptr, uint64_t cr3, CPUState *cpu)
{
    int pointer_count,
        handle_count;
    uint8_t typeindex;
    uint8_t infomask;

    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&pointer_count, sizeof(pointer_count), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#PointerCount") != -1)
        if (pointer_count > MAX_POINTER_NUMBER || pointer_count < 0)
            return 0;

    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&handle_count, sizeof(handle_count), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#HandleCount") != -1)
        if (handle_count > MAX_HANDLE_NUMBER || handle_count < 0 )
            return 0;

    // # This specifies the order the headers are found below the _OBJECT_HEADER
    // optional_header_mask = (
    //     ('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
    //     ('NameInfo',    '_OBJECT_HEADER_NAME_INFO',    0x02),
    //     ('HandleInfo',  '_OBJECT_HEADER_HANDLE_INFO',  0x04),
    //     ('QuotaInfo',   '_OBJECT_HEADER_QUOTA_INFO',   0x08),
    //     ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
    //     ('AuditInfo',   '_OBJECT_HEADER_AUDIT_INFO',   0x20),
    //     ('PaddingInfo', '_OBJECT_HEADER_PADDING_INFO', 0x40)
    // )
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&infomask, sizeof(infomask), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#InfoMask") != -1)
        if (infomask > 0x7f)
            return 0;

    // the range of type index is 2 to about 53 ,
    // lower bound is 2, but higher bound depending on Windows version
    if (memfrs_get_mem_struct_content( cpu, cr3, (uint8_t*)&typeindex, sizeof(typeindex), handle_table_entry_ptr, false, "_OBJECT_HEADER", 1, "#TypeIndex") != -1)
        if (typeindex >53 || typeindex < 1)
            return 0;

    return 1;
}



/*******************************************************************
/// find handle table entry in level 0 from handle table
///
/// \param level1_index     the index of level 1
/// \param level0_ptr       the address of level 0
/// \param cr3              the current cr3
/// \param process          the UT_array structure with handles data of one process
/// \param cpu              the pointer to current cpu
///
/// no return value
*******************************************************************/
static void do_table_level_0(int level1_index, uint64_t level0_ptr, uint64_t cr3, UT_array *process, CPUState *cpu)
{
    int i;
    uint64_t handle_table_entry_ptr,
             granted_access;

    // every 0x10 stored a handle table entry address in level 0 of handle table
    for (i=1 ; i<=256 ; ++i){
        level0_ptr = level0_ptr+0x10;
        cpu_memory_rw_debug(cpu, level0_ptr, (uint8_t*)&handle_table_entry_ptr, sizeof(handle_table_entry_ptr), 0);

        // # The handle table format
        // Instead of storing the full 64-bit pointer to the object header, 
        // Windows now only stores a 44 bit pointer.
        // The bottom four bits are inferred to be all zeroes as all 64-bit allocations, code,
        // and stack locations are 16-byte aligned,
        // while the top sixteen bits are inferred to be all ones.
        handle_table_entry_ptr = (((handle_table_entry_ptr & 0xfffffffffff00000) >> 16) + 0xffff000000000000);

        // check whether handle table entry is legal
        if (entry_is_legal(handle_table_entry_ptr, cr3, cpu) == 0)
            continue;

        // [TODO] meaning of granted access still unknow
        cpu_memory_rw_debug(cpu, level0_ptr+0x8, (uint8_t*)&granted_access, sizeof(granted_access), 0);
        granted_access = granted_access & GRANTED_ACCESS_MASK;

        // there are 256 level0 address records in a level1 table
        do_table_entry(i+level1_index*256, handle_table_entry_ptr, granted_access, cr3, process, cpu);
    }
}



/*******************************************************************
/// find level 0 in level 1 from handle table
/// 
/// \param level2_index     the index of level 2 table
/// \param level1_ptr       the address of level 1
/// \param cr3              the current cr3
/// \param process          the UT_array structure with handles data of one process
/// \param cpu              the pointer to current cpu
///
/// no return value
*******************************************************************/
static void do_table_level_1(int level2_index, uint64_t level1_ptr, uint64_t cr3, UT_array *process, CPUState *cpu)
{
    int i=0;
    uint64_t level0_ptr;

    // every level 0 address record in level 1 of handle table is 64bits
    while (i<512 && cpu_memory_rw_debug(cpu, level1_ptr, (uint8_t*)&level0_ptr, sizeof(level0_ptr), 0) != -1) {
        if (level0_ptr == 0x0)
            break;

        // there are 256 level1 address records in a level2 table
        do_table_level_0(i+level2_index*256, level0_ptr, cr3, process, cpu);
        i = i+1;
        level1_ptr = level1_ptr+0x8;
    }
}



/*******************************************************************
/// find level 1 in level 2 from handle table
///
/// \param level2_ptr   the address of level 2 table
/// \param cr3          the current cr3
/// \param process      the UT_array structure with handles data of one process
/// \param cpu          the pointer to current cpu
///
/// no return value
*******************************************************************/
static void do_table_level_2(uint64_t level2_ptr, uint64_t cr3, UT_array *process, CPUState *cpu)
{
    /* [XXX] Not yet find level2 sample */

    int i = 0;
    uint64_t level1_ptr;

    while (cpu_memory_rw_debug( cpu, level2_ptr, (uint8_t*)&level1_ptr, sizeof(level1_ptr), 0) !=-1) {
        if (level1_ptr == 0x0)
            break;
        do_table_level_0(i, level1_ptr, cr3, process, cpu);
        i = i+1;
        level2_ptr = level2_ptr+0x8;
    }
}



// handles node destructor
static void handles_node_dtor(void *_elt) {
    handles_node_st *elt = (handles_node_st*)_elt;
    if(elt->type) free(elt->type);
    if(elt->detail) free(elt->detail);
}

// handles destructor
static void handles_dtor(void *_elt) {
    handles_st *elt = (handles_st*)_elt;
    if(elt->handles_node) utarray_free(elt->handles_node);
}

UT_icd hanldes_node_icd = {sizeof(handles_node_st), NULL, NULL, handles_node_dtor};
UT_icd hanldes_icd = {sizeof(handles_st), NULL, NULL, handles_dtor};



extern UT_array* memfrs_enum_proc_handles(int target_type, uint64_t target, CPUState *cpu)
{
    // final return
    UT_array *process_handles,
             *process_handles_node;
    handles_st handles;
    
    uint64_t kpcr_ptr = memfrs_get_kpcr_ptr();

    int process_count = 0;
    uint64_t cr3,
             kthread_ptr,
             eprocess_ptr_init = 0,
             eprocess_ptr,
             tablecode_ptr;
    uint64_t processid;
    uint8_t imagename[MAX_IMAGENAME_SIZE];
    int table_level;

    int offset_entry_list_to_eprocess = 0;


    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }
    // Check if the global data structure information is loaded
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }
    // Check if kpcr is already found
    if (kpcr_ptr == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return NULL;
    }
    // Check the cpu pointer valid
    if (cpu == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return NULL;
    }

    // Read the concrete memory value of kthread_ptr(CurrentThread) via _KPCR address
    memfrs_get_mem_struct_content( cpu, 0, (uint8_t*)&kthread_ptr, sizeof(kthread_ptr), kpcr_ptr, false, "_KPCR", 2, "#Prcb", "#CurrentThread");

    // Read the concrete memory value of PROCESS via CurrentThread
    // Get the first PROCESS
    memfrs_get_mem_struct_content( cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), kthread_ptr, false, "_KTHREAD", 1, "#Process");

    // Get ActiveProcessLinks offset from _EPROCESS
    memfrs_get_nested_field_offset(&offset_entry_list_to_eprocess, "_EPROCESS", 1, "ActiveProcessLinks");

    // Get Body offset from _OBJECT_HEADER
    memfrs_get_nested_field_offset(&g_body_to_object_header, "_OBJECT_HEADER", 1, "Body");


    // Assign process_handles to be a 'handles_st' structure UTarray
    utarray_new(process_handles, &hanldes_icd);


    // Start iteration process list
    eprocess_ptr_init = eprocess_ptr;

    do {
        //Read cr3 & Process name
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&cr3, sizeof(cr3), eprocess_ptr, false, "_EPROCESS", 2, "#Pcb", "#DirectoryTableBase");
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)imagename, sizeof(imagename), eprocess_ptr, false, "_EPROCESS", 1, "#ImageFileName");
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&processid, sizeof(processid), eprocess_ptr, false, "_EPROCESS", 1, "#UniqueProcessId");

        if (cr3 == 0)
            continue;

        // pid may not greater than 65536
        if (processid > 65536) {
            free(process_handles);
            memfrs_errno = MEMFRS_ERR_INVALID_EPROCESS;
            return NULL;
        }


        utarray_new(process_handles_node, &hanldes_node_icd);


        if (
            target_type == PARSING_HANDLE_TYPE_ALL
        || (target_type == PARSING_HANDLE_TYPE_CR3 && target == cr3)
        || (target_type == PARSING_HANDLE_TYPE_EPROCESS && target == eprocess_ptr)
        || (target_type == PARSING_HANDLE_TYPE_PID && target == processid)
        ) {
            memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&tablecode_ptr, sizeof(tablecode_ptr), eprocess_ptr, false, "_EPROCESS", 2, "*ObjectTable", "#TableCode");
            table_level = tablecode_ptr & TABLE_LEVEL_MASK;
            tablecode_ptr = tablecode_ptr & TABLE_CODE_MASK;

            // table level == 0 means we are at the bottom level and this is a table of _HANDLE_TABLE_ENTRY
            // otherwise, it means we are a table of pointers to lower tables.
            if (table_level == 0)
                do_table_level_0(0, tablecode_ptr, cr3, process_handles_node, cpu);

            else if (table_level == 1)
                do_table_level_1(0, tablecode_ptr, cr3, process_handles_node, cpu);

            else 
                do_table_level_2(tablecode_ptr, cr3, process_handles_node, cpu);

            handles.cr3 = cr3;
            handles.eprocess = eprocess_ptr;
            handles.pid = processid;
            snprintf(handles.imagename, MAX_IMAGENAME_SIZE, "%s", imagename);
            handles.handles_node = process_handles_node;
            utarray_push_back(process_handles, &handles);
        }

        // Max number of process in windows is 65536.
        // Checking process count to prevent initial eprocess address error from listing process not stop.
        process_count++;
        if (process_count > 65536)
            break;

        // Read next entry
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), eprocess_ptr, false, "_EPROCESS", 2, "#ActiveProcessLinks", "*Blink");
        // Substract entry_list offset to find base address of eprocess
        eprocess_ptr = eprocess_ptr - offset_entry_list_to_eprocess;
    } while (eprocess_ptr != eprocess_ptr_init);

    return process_handles;
}



extern UT_array* memfrs_enum_proc_handles_detail(int target_type, const char *target, CPUState *cpu)
{
    // final return
    UT_array *process_handles,
             *process_handles_node;
    handles_st handles;

    //tmp handles
    UT_array *tmp_process_handles;
    handles_st *tmp_handles;
    handles_node_st *tmp_handles_node;

    int has_entry;

    tmp_process_handles = memfrs_enum_proc_handles(PARSING_HANDLE_TYPE_ALL, 0, cpu);
    if (tmp_process_handles == NULL)
        return NULL;


    // Assign process_handles to be a 'handles_st' structure UTarray
    utarray_new(process_handles, &hanldes_icd);


    tmp_handles = NULL;
    while ((tmp_handles = (handles_st*)utarray_next(tmp_process_handles, tmp_handles))) {
        tmp_handles_node = NULL;
        has_entry = 0;

        // Assign process_handles to be a 'handles_nodest' structure UTarry
        utarray_new(process_handles_node, &hanldes_node_icd);

        while ((tmp_handles_node = (handles_node_st*)utarray_next(tmp_handles->handles_node, tmp_handles_node))) {
            if (
                (target_type == PARSING_HANDLE_TYPE_TYPE && strcmp(tmp_handles_node->type, target) == 0)
            ||  (target_type == PARSING_HANDLE_TYPE_FULL_DETAIL && strcmp(tmp_handles_node->detail, target) == 0)
            ||  (target_type == PARSING_HANDLE_TYPE_DETAIL && strstr(tmp_handles_node->detail, target))
            ) {
                has_entry=1;

                add_handle_field_to_struct(
                        process_handles_node, 
                        tmp_handles_node->handle_table_entry_index, 
                        tmp_handles_node->handle_table_entry_address, 
                        tmp_handles_node->granted_access,
                        tmp_handles_node->type, 
                        tmp_handles_node->detail);
            }
        }

        if(has_entry) {
            handles.cr3 = tmp_handles->cr3;
            handles.eprocess = tmp_handles->eprocess;
            handles.pid = tmp_handles->pid;
            snprintf(handles.imagename, MAX_IMAGENAME_SIZE, "%s", tmp_handles->imagename);
            handles.handles_node = process_handles_node;

            utarray_push_back(process_handles, &handles);
        }
        else
            free(process_handles_node);
    }

    free(tmp_process_handles);
    return process_handles;
}



extern UT_array* memfrs_enum_handles_types(CPUState *cpu)
{
    int i;
    // final return 
    UT_array *handles_types = NULL;

    uint64_t kpcr_ptr = memfrs_get_kpcr_ptr();

    uint64_t object_type_ptr,
             type_buf_ptr;
    int type_index;
    char *type_name = NULL;
    char type_buf[256];     // the type name size is not greater than 256
    uint16_t length;

    uint64_t nt_kernel_base = 0,
             global_ObTypeIndexTable_ptr;
    json_object *gvar = NULL;
    int offset_name_to_object_type = 0;

    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }
    // Check if the global data structure information is loaded
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }
    // Check if kpcr is already found
    if (kpcr_ptr == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return NULL;
    }
    // Check the cpu pointer valid
    if (cpu == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return NULL;
    }


    // Get Name offset from _OBJECT_TYPE
    if (memfrs_get_nested_field_offset(&offset_name_to_object_type, "_OBJECT_TYPE", 1, "Name") == -1)
        return NULL;

    // Get global variable "ObTypeIndexTable" address 
    nt_kernel_base = memfrs_get_nt_kernel_base();
    if(nt_kernel_base == 0)
        nt_kernel_base = memfrs_find_nt_kernel_base(cpu);
    gvar = memfrs_q_globalvar("ObTypeIndexTable");
    global_ObTypeIndexTable_ptr = memfrs_gvar_offset(gvar) + nt_kernel_base;


    // Assign process_handles to be a 'ut_string' structure UTarry
    utarray_new(handles_types, &ut_str_icd);


    // The number of object type is up to 256.
    // Every entry of a type_index in ObTypeIndexTable occupies 8 byte as a type_index address.
    for (type_index = 0 ; type_index < 256 ; ++type_index) {
        if (cpu_memory_rw_debug(cpu, global_ObTypeIndexTable_ptr + 0x8*type_index, (uint8_t*)&object_type_ptr, sizeof(object_type_ptr), 0) == 0) {
            if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&length, sizeof(length), object_type_ptr, false, "_OBJECT_TYPE", 2, "#Name", "#Length") == -1)
                continue;
            if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&type_buf_ptr, sizeof(type_buf_ptr), object_type_ptr, false, "_OBJECT_TYPE", 2, "#Name", "*Buffer") == -1)
                continue;
            if (memfrs_get_virmem_content(cpu, 0, type_buf_ptr, sizeof(type_buf), (uint8_t*)type_buf) == -1)
                continue;

            // change unicode to ascii
            type_name=(char*)malloc(length/2+1);
            for (i=0 ; i<length ; i+=2)
                type_name[i/2] = (char)(*(type_buf+i));
            type_name[length/2] = '\0';

            utarray_push_back(handles_types, &type_name);
        }
    }

    return handles_types;
}
