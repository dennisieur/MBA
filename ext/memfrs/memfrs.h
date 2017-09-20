/*
 *  MBA Virtual Machine Memory Introspection header
 *
 *  Copyright (c)   2016 Chiawei Wang
 *                  2016 ChongKuan Chen
 *                  2016 ELin Ho
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



#ifndef __MEMFRS_H__
#define __MEMFRS_H__

#include <stdbool.h>
#include <inttypes.h>

#if !defined(CONFIG_MEMFRS_TEST)
#include "qom/cpu.h"
#include "json-c/json.h"
#include "include/utarray.h"
#include "include/uthash.h"
#endif

#define STRLEN 128



// Error code
typedef enum MEMFRS_ERRNO {
    MEMFRS_NO_ERR,
    MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE,
    MEMFRS_ERR_NOT_LOADED_NETWORK_STRUCTURE,
    MEMFRS_ERR_NOT_LOADED_STRUCTURE,
    MEMFRS_ERR_NOT_FOUND_KPCR,
    MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE,
    MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE_INFO,
    MEMFRS_ERR_NOT_FOUND_KERNEL_BASE,
    MEMFRS_ERR_NOT_FOUND_WINDOWS_KERNEL,
    MEMFRS_ERR_NOT_FOUND_PDB_PARSER,
    MEMFRS_ERR_NOT_FOUND_JSON_FIELD,
    MEMFRS_ERR_ALLOC_FAILED,
    MEMFRS_ERR_MEMORY_READ_FAILED,
    MEMFRS_ERR_INVALID_MBA_MEMFRS_COMMAND,
    MEMFRS_ERR_INVALID_CPU,
    MEMFRS_ERR_INVALID_EPROCESS,
    MEMFRS_ERR_INVALID_JSON_OBJ,
    MEMFRS_ERR_COMMAND_EXECUTE_FAILED
}MEMFRS_ERRNO;
extern MEMFRS_ERRNO memfrs_errno;



// Represent the field in the data structure
typedef struct field_info {
    int offset;                     // field offset related to data structure
    char type_name[STRLEN];         // the type name
    int type_size;                  // the size of the field
    bool is_pointer;                // idicate if the field is pointer
    int pointer_dereference_count;  // pointer dereference count
    json_object* jobject_type;      // the json object to the field type
}field_info;


// Kernel module
typedef struct kernel_module {
    char fullname[256];         // unicode max length is 256
    char basename[256];         // unicode max length is 256
    uint64_t virtual_addr;      // virtual address
    uint64_t image_size;        // image size
}kernel_module_st;


// Reverse lookup table for address -> symbol name
typedef struct reverse_symbol {
    int offset;                 // we'll use this field as the key
    char* symbol;               // symbol name
    UT_hash_handle hh;          // makes this structure hashable
}reverse_symbol;


// Current thread data
typedef struct current_thread {
    uint64_t tid;               // thread id
    uint64_t pid;               // process id
    char image_file_name[16];   // image file name, the max length is 16
}current_thread;


// Data node in process list
typedef struct process_list_st {
    uint64_t eprocess;          // the process' eprocess
    uint64_t cr3;               // the process' cr3
    uint64_t pid;               // the process' process id
    char *full_file_path;       // the process' full file path (not include command)
                                //     if full file path can't find in data struct
                                //     only stored the file name.
}process_list_st;


// Data node in handles list
typedef struct handles_node_st {
    int handle_table_entry_index;           // the process' handle table entry index
    uint64_t handle_table_entry_address;    // the process' handle table entry address
    uint64_t granted_access;                // the handle's granted access
    char *type;                             // the handle's type
    char *detail;                           // the handle's detail
}handles_node_st;


// Data in handles list
typedef struct handles_st {
    uint64_t cr3;               // the process' cr3
    uint64_t eprocess;          // the process' eprocess
    uint64_t pid;               // the process' process id
    char imagename[16];         // the process' file name, the max length is 16
    UT_array *handles_node;     // handles node store the target process' handles
}handles_st;



// hive list
typedef struct hive_list_st{
    uint64_t CMHIVE_address;    // the hive root structure address
    char *file_full_path;       // file_full_path
    char *file_user_name;       // file_user_name
    char *hive_root_path;       // hive root path
}hive_list_st;



// Data node in SSDT list
typedef struct ssdt_list_st {
    int      index;             // system call index, from 0 to number of system call
    uint64_t address;           // the system call actually virtual address
    int      argnum_on_stack;   // number of argument of stack
    char system_call_name[128]; // system call name might not longer than 128
}ssdt_list_st;


// Data node in network object list
typedef struct network_state {
    const char *protocol;       // UdpA, TcpL or TcpE
    uint64_t pmem;              // physical memory address
    uint64_t eprocess;          // eprocess
    char imagename[16];         // Max image name length is 15, i char for '\0'
    uint64_t pid;               // process id
    const char* state;          // the tcp endpoint state
    char local_addr[46];        // Max address size is 46 for ipv6 ip + port
    char foreign_addr[46];      // Max address size is 46 for ipv6 ip + port
    char time[26];              // last edited time
}network_state;



// public API



/*******************************************************************
/// Find kernel base address 
///
/// \param cpu              current cpu
///
/// return kernel base address, return 0 if not found
*******************************************************************/
extern uint64_t memfrs_find_nt_kernel_base(CPUState* cpu);



/*******************************************************************
/// Get kernel base address
///
/// \no input
///
/// return kernel base address, return 0 if not found
*******************************************************************/
extern uint64_t memfrs_get_nt_kernel_base(void);



/*******************************************************************
/// Get kernel information
///
/// \not input
///
/// return kernel information, return NUU if not found
*******************************************************************/
extern void* memfrs_get_kernel_info(void);



/*******************************************************************
/// Generate PDB profiles
///
/// \param profile_dir
///
/// return -1 on error, 0 on success
*******************************************************************/
extern int memfrs_gen_pdb_profiles(const char* profile_dir);



/*******************************************************************
/// Hueristic check if certain address contain the data structure _KPCR
///
/// \param kpcr_ptr         the 64bit address of possible KPCR pointer
///
/// return true if kpcr found, else retuen false
*******************************************************************/
extern bool memfrs_kpcr_self_check(uint64_t seg_gs_cpl0);



/*******************************************************************
/// Set the address of the KPCR
///
/// no return value
*******************************************************************/
extern void memfrs_set_kpcr_ptr(uint64_t kpcr_ptr);



/*******************************************************************
/// Get the address of the KPCR
///
/// return the address of KPCR
*******************************************************************/
extern uint64_t memfrs_get_kpcr_ptr(void);



/*******************************************************************
/// Query the data structure's info via given structure name
///
/// \param ds_name     the name of interesting structure
///
/// return json object representation of the target struct
*******************************************************************/
extern json_object* memfrs_q_struct(const char* ds_name);



/*******************************************************************
/// Given the structure's json object, q_field return the field information
/// of given field_name
///
/// \param struc        json object of structure we want to query
/// \param field_name   the target name we want to find
///
/// return the field information of given field_name in type if field_info
*******************************************************************/
extern field_info* memfrs_q_field(json_object* struc, const char* field_name);



/*******************************************************************
/// Load the data structure information into g_struct_info
///
/// \param type_filename        the filename of json data structure database
///
/// return 0 if sucess, and not 0 otherwise
*******************************************************************/
extern int memfrs_load_structs(const char* type_filename);



/*******************************************************************
/// Load the global variable information into g_globalvar_info
///
/// \param gvar_filename        the filename of json global variable database
///
/// return 0 if sucess, and not 0 otherwise
*******************************************************************/
extern int memfrs_load_globalvar(const char* type_filename);



/*******************************************************************
/// Check whether struct has been load
///
/// \no input
///
/// return true if loaded struct, return false if not loded.
*******************************************************************/
extern bool memfrs_check_struct_info(void);



/*******************************************************************
/// Check whether global struct has been load
///
/// \no input
///
/// return true if loaded global struct, return false if not loded.
*******************************************************************/
extern bool memfrs_check_globalvar_info(void);



/*******************************************************************
/// Scan the virtual memory for the specific pattern
///
/// \param cpu              current cpu
/// \param start_addr       start address
/// \param end_addr         end address
/// \param pattern          Search pattern
/// \param length           length of pattern
///
/// return NULL if cannot allocate memory for do_show_memory_taint_map(),
/// otherwise return an UT_array with type uint64_t
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_scan_virmem(CPUState *cpu, uint64_t start_addr, uint64_t end_addr, const char* pattern, int length);


/*******************************************************************
/// Scan for specific pattern in the VM's physical memory
///
/// \param start_addr       The start address
/// \param end_addr         the end address
/// \param pattern          pattern to search, support only ascii string
///
/// return an UT_array that contains the address of found pattern,
/// the type of UT_array is uint64_t
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_scan_phymem(uint64_t start_addr, uint64_t end_addr, const char* pattern, int length);



/*******************************************************************
/// Get the memory content in virtual memory
///
/// \param cpu                  Current cpu
/// \param cr3                  cr3 value, 0 if no specific process
/// \param target_addr          The target address
/// \param target_length        The length to be getten
/// \param buf                  The buffer to save the memory content
///
/// -1 indicate fails
*******************************************************************/
extern int memfrs_get_virmem_content(CPUState *cpu, uint64_t cr3, uint64_t target_addr, uint64_t target_length, uint8_t* buf);



/*******************************************************************
/// Query the global variable's info via given variable name
///
/// \param gvar_name        the name of interesting global symbol
///
/// json object representation of the target global var
*******************************************************************/
extern json_object* memfrs_q_globalvar(const char* gvar_name);



/*******************************************************************
/// Get the virtual address of specific global variable, which is in
/// json_object format.
///
/// \requried           memfrs_q_globalvar should be invoked befor invoke this API
///
/// \param gvarobj      the json obj of interesting global symbol
///
/// return the virtual address of specific global variable, -1 indicates fails
*******************************************************************/
extern int64_t memfrs_gvar_offset(json_object* gvarobj);



/*******************************************************************
/// Load global variable to reverse symbol table
///
/// no input
///
/// return reverse_symbol_table
*******************************************************************/
extern reverse_symbol* memfrs_build_gvar_lookup_map(void);



/*******************************************************************
/// Get the symbol name at specific virtual memory address from reverse symbol table
///
/// \param rsym_tab     reverse_symbol_table
/// \param offset       target offset, the offset is an offset to kernel base address
///
/// return symbol name
*******************************************************************/
extern char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset);



/*******************************************************************
/// Free reverse symbol table
///
/// \param rsym_tab     reverse_symbol_table
///
/// return 0 if sucess, and not 0 otherwise
/// \MUST FREE this return object using 'memfrs_free_reverse_lookup_map(object)'
*******************************************************************/
extern int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab);



/*****************************************************************
/// Guess windows version
///
/// \required       load the data structure information
/// \required       load the global data structure information
///
/// \param cpu      the pointer to current cpu
///
/// return windows version code
///
/// Version number  Operating system
///     -1.0         [ERROR] Need to check error code
///      0.0         [Unknown] Unknown version
///     10.0         Windows 10
///     10.0         Windows Server 2016
///      6.3         Windows 8.1
///      6.3         Windows Server 2012 R2
///      6.2         Windows 8
///      6.2         Windows Server 2012
///      6.1         Windows 7
///      6.1         Windows Server 2008 R2
///      6.0         Windows Server 2008
///      6.0         Windows Vista
///      5.2         Windows Server 2003 R2
///      5.2         Windows Server 2003
///      5.2         Windows XP 64-Bit Edition
///      5.1         Windows XP
///      5.0         Windows 2000
*******************************************************************/
extern float memfrs_get_windows_version(CPUState *cpu);



/*******************************************************************
/// Get current thread datas
///
/// \required       load the data structure information
///
/// \param cpu      the pointer to current cpu
///
/// return type current_thread
*******************************************************************/
extern current_thread *memfrs_get_current_thread(CPUState *cpu);



/*******************************************************************
/// Eumerate the running process
///
/// \required       load the data structure information
///
/// \param cpu      the pointer to current cpu
///
/// return an UT_array with type process_list_st
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_enum_proc_list(CPUState *cpu);



/*******************************************************************
/// Eumerate the running process handles
///
/// \required       load the data structure information
/// \required       load the global data structure information
///
/// \param target_type      searching type of handles
/// \param target           searching target
/// \param kpcr_ptr         the address of _KPCR struct
/// \param cpu              the pointer to current cpu
///
/// return an UT_array with type handles_st
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_enum_proc_handles(int target_type, uint64_t target, CPUState *cpu);



/*******************************************************************
/// Eumerate the running process handles, expect for types and details
///
/// \required       load the data structure information
/// \required       load the global data structure information
///
/// \param target_type      searching type of handles
/// \param target           searching target
/// \param cpu              the pointer to current cpu
///
/// return an UT_array with type handles_st
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_enum_proc_handles_detail(int target_type, const char* target, CPUState *cpu);



/*******************************************************************
/// Eumerate the handles types
///
/// \required       load the data structure information
/// \required       load the global data structure information
///
/// \param cpu      the pointer to current cpu
///
/// return an UT_array with type ut_string
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_enum_handles_types(CPUState *cpu);



/*****************************************************************n
/// Eumerate the hive file
///
/// \required       load the data structure information
/// \required       load the global data structure information
///
/// \param cpu          the pointer to current cpu
///
/// return a UT_array with ssdt data
*******************************************************************/
extern UT_array* memfrs_enum_hive_list(CPUState *cpu);



/*******************************************************************
/// Eumerate the ssdt
///
/// \required       load the global data structure information
///
/// \param kpcr_ptr     kpcr address
/// \param cpu          the pointer to current cpu
///
/// return an UT_array with type ssdt_list_st
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_enum_ssdt_list(CPUState *cpu);



/*****************************************************************n
/// Dump target hive file to a file.
/// 
/// \required       load the data structure information
///
/// \param cpu                  the pointer to current cpu
/// \param fd                   the file discriptor
/// \param CMHIVE_address       the target hive file head address
///
/// return 0 for success, -1 for error
*******************************************************************/
extern int memfrs_registry_dump(CPUState *cpu, FILE*fd, uint64_t CMHIVE_address);



/*******************************************************************
/// Scan the whole physical memory for MmLd Module tag, and list all the module name in atdout.
///
/// \required       load the data structure information
///
/// \param cpu      pointer to current cpu
///
/// return an UT_array with type kernel_module_st
/// \MUST FREE this return object using 'utarray_free(object)'
*******************************************************************/
extern UT_array* memfrs_scan_module(CPUState *cpu);



/*********************************************************************************
/// Scan the whole physical memory for network pool tag, and list all the network state.
///
/// \required       load the data structure information
/// \required       load the network data structure information
///
/// \param cpu      pointer to current cpu
///
/// return an UT_array with type network_state
/// \MUST FREE this return object using 'utarray_free(object)'
**********************************************************************************/
extern UT_array* memfrs_scan_network(CPUState *cpu);



/*******************************************************************
/// Fit the memory at addr into structure fields
///
/// \required       load the data structure information
///
/// \param mon              Monitor
/// \param cpu              current cpu
/// \param addr             address
/// \param struct_name      struct name
///
/// return 0 for success
*******************************************************************/
extern int memfrs_display_type(Monitor *mon, CPUState *cpu, uint64_t addr, const char* struct_name);



/*********************************************************************************
/// 1. Get vad root node by the eprocess_ptr
/// 2. Traversal vad tree, which is AVL tree
///
/// \param eprocess_ptr     the virtual address to the eprocess structure
/// \param *cpu             pointer to current cpu
///
/// return an UT_array with type vad_node
/// \MUST FREE this return object using 'utarray_free(object)'
**********************************************************************************/
extern UT_array* memfrs_traverse_vad_tree(uint64_t eprocess_ptr, CPUState *cpu);



/*********************************************************************************
/// Get field content of some struct in virtual memory
///
/// e.g. To get content of following structure,
/// which struct A *p = 0xdeadbeef in guest virtual memory:
/// struct A {
///     struct B field1;
/// };
/// struct B {
///     struct C *field2;
/// };
/// struct C {
///     uint64_t field3;
/// };
///
/// memfrs_get_mem_struct_content(cpu, cr3, buffer, sizeof(uint64_t), 0xdeadbeef, "A", false,
///         3, "#field1", "*field2", "#field3");
/// 
/// \param cpu              the running cpu
/// \param cr3              cr3 register of target virtual memory space
/// \param buffer           output buffer
/// \param len              length of content to read
/// \param struct_addr      the virtual address of the target structure
/// \param bool             from_physical_memory,
/// \param struct_type_name the type name of the target structure
/// \param depth            the field access chain depth
/// \param ...              field names in the query chain
/// 
/// return -1 on error, 0 on success
**********************************************************************************/
extern int memfrs_get_mem_struct_content(
        CPUState   *cpu,
        uint64_t    cr3,
        uint8_t    *buffer,
        int         len,
        uint64_t    struct_addr,
        bool        from_physical_memory,
        const char *struct_type_name,
        int         depth,
        ...);



/*********************************************************************************
/// Get nested field offset
///
/// \param out                  offset output
/// \param struct_type_name     the type name of the target structure
/// \param  depth               the field access chain depth
/// \param ...                  field names in the query chain
///
/// return -1 on error, 0 on success
**********************************************************************************/
extern int memfrs_get_nested_field_offset(
        int *out,
        const char *struct_type_name,
        int depth,
        ...);



/*********************************************************************************
/// Get last error message
///
/// \no input
///
/// return error message with type const char* string
**********************************************************************************/
extern const char* memfrs_get_last_error_message(void);



#endif
