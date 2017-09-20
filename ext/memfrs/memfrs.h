/*
 *  MBA Virtual Machine Memory Introspection header
 *
 *  Copyright (c)   2016 Chiawei Wang
 *                  2016 ChongKuan Chen
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
#define SIZEOFUNICODESTRING 0x10


extern uint64_t g_kpcr_ptr;

typedef enum MEMFRS_ERRNO{
    MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE,
    MEMFRS_ERR_NOT_LOADED_STRUCTURE,
    MEMFRS_ERR_NOT_FOUND_KPCR,
    MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE,
    MEMFRS_ERR_NOT_FOUND_KERNEL_BASE,
    MEMFRS_ERR_MEMORY_READ_FAILED,
    MEMFRS_ERR_INVALID_CPU
}MEMFRS_ERRNO;
extern MEMFRS_ERRNO memfrs_errno;

// current thread datas
typedef struct current_thread
{
    uint64_t unique_thread;
    uint64_t unique_process;
    char* image_file_name;
} current_thread;

// represent the field in the data structure
typedef struct field_info
{
    int offset;                    // field offset related to data structure  
    char type_name[STRLEN];
    int type_size;                 // the size of the field
    bool is_pointer;               // idicate if the field is pointer
    int pointer_dereference_count;               // idicate if the field is pointer
    json_object* jobject_type;     // the json object to the field type
} field_info;

typedef struct reverse_symbol {
    int offset;            /* we'll use this field as the key */
    char* symbol;
    UT_hash_handle hh; /* makes this structure hashable */
} reverse_symbol;

// public API 
/*******************************************************************
bool memfrs_check_struct_info(void)
Check whether struct has been load.
INPUT:  no input
OUTPUT: bool                    return 1 if loaded struct.
*******************************************************************/
extern bool memfrs_check_struct_info(void);

/*******************************************************************
bool memfrs_kpcr_self_check( uint64_t kpcr_ptr )
Hueristic check if certain address contain the data structure _KPCR
INPUT:     uint64_t kpcr_ptr,        the 64bit address of possible KPCR pointer
OUTPUT:    bool,                     return true if kpcr found, else retuen false
*******************************************************************/
extern bool memfrs_kpcr_self_check( uint64_t seg_gs_cpl0 );

/*****************************************************************
float memfrs_get_windows_version( uint64_t kpcr_ptr, CPUState *cpu )
Guess windows version
INPUT:     uint64_t kpcr_ptr,        the address of _KPCR struct
           CPUState *cpu,            the pointer to current cpu
OUTPUT:    float                     windows version
Version number  Operating system
    -1.0         [ERROR] Need to check error code
     0.0         [Unknown] Unknown version
    10.0         Windows 10
    10.0         Windows Server 2016
     6.3         Windows 8.1
     6.3         Windows Server 2012 R2
     6.2         Windows 8
     6.2         Windows Server 2012
     6.1         Windows 7
     6.1         Windows Server 2008 R2
     6.0         Windows Server 2008
     6.0         Windows Vista
     5.2         Windows Server 2003 R2
     5.2         Windows Server 2003
     5.2         Windows XP 64-Bit Edition
     5.1         Windows XP
     5.0         Windows 2000
*******************************************************************/
extern float memfrs_get_windows_version( uint64_t kpcr_ptr, CPUState *cpu );

/*******************************************************************
current_thread *memfrs_get_current_thread(void)
Get current thread datas
INPUT:    CPUState *cpu
OUTPUT:   current_thread*           current_thread
*******************************************************************/
extern current_thread *memfrs_get_current_thread( CPUState *cpu );

extern bool memfrs_check_network_struct_info(void);
extern bool memfrs_check_globalvar_info(void);

/*******************************************************************
int memfrs_load_structs( const char* type_filename)
Load the data structure information into g_struct_info.
INPUT:     const char* type_filename,  the filename of json data structure database
OUTPUT:    int,                        return 0 if sucess, and not 0 otherwise
*******************************************************************/
extern int memfrs_load_structs( const char* type_filename);

/*******************************************************************
json_object* memfrs_q_struct(const char* ds_name)
query the data structure's info via given structure name
INPUT:    const char* ds_name,  the name of interesting structure
OUTPUT:   json_object*,         json object representation of the target struct
*******************************************************************/
extern json_object* memfrs_q_struct(const char* ds_name);

/*******************************************************************
field_info* memfrs_q_field( json_object* struc, const char* field_name  )
Given the structure's json object, q_field return the field information
of given field_name.
INPUT: json_object* struc       json object of structure we want to query
       const char* field_name   the target name we want to find
OUTPUT: field_info*             return the field information in type if field_info
*******************************************************************/
extern field_info* memfrs_q_field( json_object* struc, const char* field_name  );

/*******************************************************************
int memfrs_close_field(field_info* field)
free the memory of field_info.
INPUT:     field_info* field,   pointer of field_info object to be freed
OUTPUT:    int,                 return 0 if sucess, and not 0 otherwise
*******************************************************************/
extern int memfrs_close_field(field_info* field);

/*******************************************************************
UT_array* memfrs_scan_virmem( CPUState *cpu, uint64_t start_addr, uint64_t end_addr, const char* pattern, int length ) {
Scan the virmem for the specific pattern
INPUT:    CPUState *cpu          Current cpu
          uint64_t start_addr    start address
          uint64_t end_addr      end address
          const char* pattern    Search pattern
          int length             length of pattern
OUTPUT:   UT_array*              return NULL if cannot allocate memory for do_show_memory_taint_map()
*******************************************************************/
extern UT_array* memfrs_scan_virmem( CPUState *cpu, uint64_t start_addr, uint64_t end_addr, const char* pattern, int length );

/*******************************************************************
UT_array* memfrs_scan_phymem( uint64_t start_addr, uint64_t end_addr, const char* pattern )
Scan for specific pattern in the VM's physical memory
INPUT:    uint64_t start_addr,  The start address
          uint64_t end_addr,    the end address
          const char* pattern   pattern to search, support only ascii string
OUTPUT:   UT_array*,            An UT_array that contains the address of found pattern
*******************************************************************/
extern UT_array* memfrs_scan_phymem( uint64_t start_addr, uint64_t end_addr, const char* pattern, int length );

/*******************************************************************
int memfrs_get_virmem_content( CPUState *cpu, uint64_t cr3, uint64_t target_addr, uint64_t target_length, uint8_t* buf)
Get the memory content in virtual memory
INPUT:    CPUState *cpu          Current cpu
          uint64_t cr3           CR3 value, 0 if no specific process
          uint64_t target_addr   The target address 
          uint64_t target_length The length to be getten
          uint8_t* buf           The buffer to save the memory content
OUTPUT:   int                    -1 indicate fails
*******************************************************************/
extern int memfrs_get_virmem_content( CPUState *cpu, uint64_t cr3, uint64_t target_addr, uint64_t target_length, uint8_t* buf);

/*******************************************************************
int memfrs_load_structs( const char* gvar_filename)
Load the global variable information into g_globalvar_info.
INPUT:     const char* gvar_filename,  the filename of json global variable database
OUTPUT:    int,                        return 0 if sucess, and not 0 otherwise
*******************************************************************/
extern int memfrs_load_globalvar( const char* type_filename);

/*******************************************************************
json_object* memfrs_q_globalvar(const char* gvar_name)
query the global variable's info via given variable name
INPUT:    const char* gvar_name,  the name of interesting global symbol
OUTPUT:   json_object*,         json object representation of the target global var
*******************************************************************/
extern json_object* memfrs_q_globalvar(const char* gvar_name);

/*******************************************************************
uint64_t memfrs_gvar_offset(json_object* gvarobj)
Get the virtual address of specific global variable, which is in
json_object format. 
memfrs_q_globalvar should be invoked first to get the json_object.
INPUT:    json_object* gvarobj  the json obj of interesting global symbol
OUTPUT:   int64_t               the virtual address of specific global variable, -1 indicates fails
*******************************************************************/
extern int64_t memfrs_gvar_offset(json_object* gvarobj);

extern uint64_t memfrs_find_nt_kernel_base(CPUState* cpu);

extern uint64_t memfrs_get_nt_kernel_base(void);

extern UT_array* memfrs_scan_module(CPUState *cpu);

extern UT_array* memfrs_traverse_vad_tree(uint64_t eprocess_ptr, CPUState *cpu);

/*******************************************************************
reverse_symbol* memfrs_build_gvar_lookup_map(void)
Load global variable to reverse_symbol_table
INPUT:    void
OUTPUT:   reverse_symbol*       reverse_symbol_table
*******************************************************************/
extern reverse_symbol* memfrs_build_gvar_lookup_map(void);

/*******************************************************************
char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset)
get the symbolname at specific virtual memory address from reverse_symbol_table
INPUT:    reverse_symbol* rsym_tab  reverse_symbol_table
          int offset                target address
OUTPUT:   char*                     symbol name
*******************************************************************/
extern char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset);

/*******************************************************************
int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab)
Free reverse_symbol_table
INPUT:    reverse_symbol* rsym_tab  
          int offset                target address
OUTPUT:   int                       return 0 for success
*******************************************************************/
extern int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab);

extern void* memfrs_get_kernel_info(void);

extern int memfrs_gen_pdb_profiles(const char* profile_dir);

/*******************************************************************
int memfrs_display_type(CPUState *cpu, uint64_t addr, const char* struct_name)
Fit the memory at addr into structure fields
INPUT:    CPUState *cpu             Current cpu
          uint64_t addr             address
          const char* struct_name   struct name
OUTPUT:   int                       return 0 for success
*******************************************************************/
extern int memfrs_display_type(CPUState *cpu, uint64_t addr, const char* struct_name);

/// get field content of some struct in virtual memory
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

extern int memfrs_get_nested_field_offset(int *out, const char *struct_type_name, int depth, ...);


#endif
