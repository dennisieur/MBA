/*
 *  MBA Virtual Machine Memory Introspection implementation
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

#if !defined(CONFIG_MEMFRS_TEST)
#include "qemu-common.h"
#include "monitor/monitor.h"
#include "include/exec/cpu-common.h"
#include "exec/cpu-all.h"
#include "include/utarray.h"
#include "include/uthash.h"
#include "json.h"
#endif

#if defined(CONFIG_MEMFRS_TEST)
#include "test/test.h"
#endif

#include "memfrs.h"
#include "memfrs-priv.h"

#if defined(CONFIG_MEMFRS_TEST)
/// Change name to avoid macros in test.h from expanding.
/// Refer to _dift_log to call original dift_log in tests.
#define _MOCKABLE(x) _##x
#else
#define _MOCKABLE(x) x
#endif

#include <stdarg.h>

/* Global Variable */
uint64_t g_kpcr_ptr = 0;
json_object *g_struct_info = NULL;
json_object *g_globalvar_info = NULL;

MEMFRS_ERRNO memfrs_errno;



/*******************************************************************
bool memfrs_check_struct_info(void)

Check whether struct has been load.

INPUT:  no input

OUTPUT: bool                    return 1 if loaded struct.
*******************************************************************/
bool memfrs_check_struct_info(void)
{
    return (g_struct_info!=NULL)? 1 : 0;
}



/*******************************************************************
field_info* memfrs_q_field( json_object* struc, const char* field_name  )

Given the structure's json object, q_field return the field information
of given field_name.

INPUT: json_object* struc       json object of structure we want to query
       const char* field_name   the target name we want to find

OUTPUT: field_info*             return the field information in type if field_info
*******************************************************************/
field_info* memfrs_q_field( json_object* struc, const char* field_name )
{
    json_object* target = NULL;
    json_object* tmp_jobject = NULL;
    field_info* f_info = NULL;
    int offset = 0;

    // Query the field in the structures(struc) by the field_name
    // Save the result into target json object
    json_object_object_get_ex(struc, field_name, &target);
    if(target == NULL)
    {
        printf("\"%s\" not found\n", field_name);
        return NULL;
    }

    // The result is the json array as ( field_type, field_offset, field_size, field_is_pointer)
    // query and unpack offset
    tmp_jobject = json_object_array_get_idx(target, 1);
    offset = json_object_get_int(tmp_jobject);

    f_info =(field_info*)malloc(sizeof(field_info));
    f_info->offset = offset;

    //query and unpack field type
    tmp_jobject = json_object_array_get_idx(target, 0);
    strncpy(f_info->type_name, json_object_get_string(tmp_jobject), STRLEN);

    //TODO: type size leave empty now
    f_info -> type_size = json_object_get_int(json_object_array_get_idx(target, 2));
    f_info -> pointer_dereference_count = json_object_get_int(json_object_array_get_idx(target, 3));
    
    if(f_info -> pointer_dereference_count > 0)
        f_info->is_pointer = true;
    else
        f_info->is_pointer = false;    

    // Put the json object of field type into fielf_info structure
    if(g_struct_info != NULL)
        json_object_object_get_ex(g_struct_info, f_info->type_name, &(f_info->jobject_type));

    return f_info;
}



/*******************************************************************
int memfrs_close_field(field_info* field)

free the memory of field_info.

INPUT:     field_info* field,   pointer of field_info object to be freed
OUTPUT:    int,                 return 0 if sucess, and not 0 otherwise

*******************************************************************/
int memfrs_close_field(field_info* field)
{
    free(field);
    return 0;
}



/*******************************************************************
json_object* memfrs_q_struct(const char* ds_name)

query the data structure's info via given structure name

INPUT:    const char* ds_name,  the name of interesting structure
OUTPUT:   json_object*,         json object representation of the target struct

*******************************************************************/
json_object* memfrs_q_struct(const char* ds_name)
{
    json_object* target = NULL;

    // Query global structure info with structure name ds_name
    // Restore the query result into target json_object
    if(g_struct_info!=NULL)
        json_object_object_get_ex(g_struct_info, ds_name, &target);
    else
        return NULL;
    
    if(target==NULL)
        printf("%s not found\n", ds_name);

    return target;
}



/*******************************************************************
int memfrs_load_structs( const char* type_filename)

Load the data structure information into g_struct_info.

INPUT:     const char* type_filename,  the filename of json data structure database
OUTPUT:    int,                        return 0 if sucess, and not 0 otherwise

*******************************************************************/
int memfrs_load_structs( const char* type_filename)
{
    json_object *struct_info = NULL, *test_obj = NULL;
    if(g_struct_info==NULL){
        g_struct_info = json_object_from_file(type_filename);
    }
    else{
        struct_info = json_object_from_file(type_filename);
        json_object_object_foreach(struct_info, key, val){
            json_object_object_get_ex(g_struct_info, key, &test_obj);
            if(test_obj!=NULL){
                printf("The json object with key %s has been overwritten.\n", key);
            }
            json_object_object_add(g_struct_info, key, val);
        }
    }

    return 0;
}



/*******************************************************************
bool memfrs_kpcr_self_check( uint64_t kpcr_ptr )

Hueristic check if certain address contain the data structure _KPCR

INPUT:     uint64_t kpcr_ptr,        the 64bit address of possible KPCR pointer
OUTPUT:    bool,                     return true if kpcr found, else retuen false
*******************************************************************/
bool memfrs_kpcr_self_check( uint64_t kpcr_ptr ) {

    uint64_t self_ptr = 0;
    json_object* test_obj;
    json_object* jkpcr =NULL;
    field_info* f_info = NULL;
    int offset_self_to_kpcr = 0;

    //Check if the global data structure info is load, if not abort check.
    if(g_struct_info == NULL)
    {
        return false;
    }

    // Find the struct _KPCR
    json_object_object_get_ex(g_struct_info, "_KPCR", &test_obj);
    if(test_obj==NULL)
        return false;

    jkpcr = memfrs_q_struct("_KPCR");
    if(jkpcr==NULL)
        return false;

    // Query field name Self in _KPCR structure
    f_info = memfrs_q_field(jkpcr, "Self");

    offset_self_to_kpcr = f_info->offset;
    memfrs_close_field(f_info);

    // Read the concrete memory value in Self field
    if( cpu_memory_rw_debug(current_cpu, kpcr_ptr + offset_self_to_kpcr, (uint8_t*)&self_ptr, sizeof(self_ptr), 0) != 0 )
    {
        g_kpcr_ptr = 0;
        return false;
    }

    // Check if the Self pointer point back to _KPCR structure, which is the hueristic check of _KPCR
    if( kpcr_ptr == self_ptr ) {
        g_kpcr_ptr = kpcr_ptr;
        printf("KPCR found %lx\n", g_kpcr_ptr);
        return true;
    }

    g_kpcr_ptr = 0;
    return false;
}



/*****************************************************************
float memfrs_get_windows_version( uint64_t kpcr_ptr, CPUState *cpu )

Guess windows version

INPUT:     uint64_t kpcr_ptr,        the address of _KPCR struct
           CPUState *cpu,            the pointer to current cpu
OUTPUT:    float                     windows version
*******************************************************************/
float memfrs_get_windows_version( uint64_t kpcr_ptr, CPUState *cpu )
{
    float version;
    json_object *struct_type;
    json_object *gvar = NULL;
    field_info *info = NULL;


    // Check if the data structure information is loaded
    if(g_struct_info == NULL)
    {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return -1.0;
    }
    //Check if the data structure information is loaded
    if(g_struct_info == NULL)
    {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return -1.0;
    }

    //Check if kpcr is already found
    if(kpcr_ptr == 0)
    {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return -1.0;
    }

    //Check the cpu pointer valid
    if(cpu == NULL)
    {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return -1.0;
    }


    version = 5.2;


    /* Followed Rekall "https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/overlays/windows/windows.py#L57"
     * Rekall is moving away from having features keyed by version, rather we
     * use the profile to dictate the algorithms to use. In future we will
     * remove all requirement to know the windows version, but for now we
     * just guess the version based on structures which are known to exist in
     * the profile.
     */


    // Windows 7 introduces TypeIndex into the object header.
    if( (struct_type = memfrs_q_struct("_OBJECT_HEADER")) != NULL && (info = memfrs_q_field(struct_type, "TypeIndex")) != NULL ){

        // Windows 10 introduces a cookie for object types.
        gvar = memfrs_q_globalvar("ObHeaderCookie");
        if( gvar != NULL )
            version = 10.0;

        // Windows 7
        else if( (struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot.BalancedRoot")) != NULL &&
                 (strcmp(info->type_name, "_MMADDRESS_NODE")==0) )
            version = 6.1;

        // Windows 8 uses _MM_AVL_NODE as the VAD traversor struct.
        else if( (struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot")) != NULL &&
                 (strcmp(info->type_name, "_MM_AVL_TABLE")==0) )
            version = 6.2;

        // Windows 8.1 and on uses _RTL_AVL_TREE
        else if( (struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot")) != NULL &&
                 (strcmp(info->type_name, "_RTL_AVL_TREE")==0) )
            version = 6.3;

        // Unknown windows version
        else
            version = 0.0;
    }

    // Windows XP did not use a BalancedRoot for VADs.
    else if( (struct_type = memfrs_q_struct("_MM_AVL_TABLE")) != NULL && (info = memfrs_q_field(struct_type, "BalancedRoot")) == NULL )
        version = 5.1;

    else
        version = 0.0;


    return version;
}



/*******************************************************************
current_thread *memfrs_get_current_thread(void)

Get current thread datas

INPUT:    CPUState *cpu
OUTPUT:   current_thread*           current_thread
*******************************************************************/
current_thread *memfrs_get_current_thread( CPUState *cpu)
{
    current_thread *thread_data=NULL;
    uint64_t thread_ptr,
             _CLIENT_ID_ptr,
             eprocess_ptr,
             pid_ptr,
             tid_ptr;
    uint64_t pid, tid;
    uint8_t image_file_name[16];        // Max size of image name in _EPROCESS is 16

    json_object *struct_type;
    field_info *info = NULL;

    if(g_kpcr_ptr){
        // Get Current thread address
        memfrs_get_mem_struct_content( cpu, 0, (uint8_t*)&thread_ptr, sizeof(thread_ptr), g_kpcr_ptr, false, "_KPCR", 2, "*CurrentPrcb", "*CurrentThread");

        // Get address of PID and TID
        struct_type = memfrs_q_struct("_ETHREAD");
        if (struct_type == NULL)
            return NULL;
        info = memfrs_q_field(struct_type, "Cid");
        _CLIENT_ID_ptr = thread_ptr + info->offset;

        struct_type = memfrs_q_struct("_CLIENT_ID");
        if (struct_type == NULL)
            return NULL;
        info = memfrs_q_field(struct_type, "UniqueProcess");
        pid_ptr = _CLIENT_ID_ptr + info->offset;
        info = memfrs_q_field(struct_type, "UniqueThread");
        tid_ptr = _CLIENT_ID_ptr + info->offset;

        // Get PID and TID
        memfrs_get_virmem_content(cpu, 0, pid_ptr, sizeof(pid), (uint8_t*)&pid);
        memfrs_get_virmem_content(cpu, 0, tid_ptr, sizeof(tid), (uint8_t*)&tid);

        // Get current image name
        memfrs_get_mem_struct_content( cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), thread_ptr, false, "_KTHREAD", 1, "*Process");
        memfrs_get_mem_struct_content( cpu, 0, (uint8_t*)&image_file_name, sizeof(image_file_name), eprocess_ptr, false, "_EPROCESS", 1, "*ImageFileName");
        image_file_name[15]='\0';

        // Set values in return structure
        thread_data = (current_thread*)malloc(sizeof(current_thread));
        thread_data->image_file_name = (char*)malloc(16);
        thread_data->unique_thread = tid;
        thread_data->unique_process = pid;
        sprintf(thread_data->image_file_name, "%s", image_file_name);
    }

    return thread_data;
}



UT_icd adr_icd = {sizeof(uint64_t), NULL, NULL, NULL };
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
// TODO: Still buggy
UT_array* memfrs_scan_virmem( CPUState *cpu, uint64_t start_addr, uint64_t end_addr, const char* pattern, int length ) {
    uint64_t i;

    if(start_addr >= end_addr){
        printf("end_addr is not less than start_addr\n");
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(length);
    UT_array *match_addr;

    memset(buf, 0, length);

    if(buf == NULL){
        printf("Cannot allocate memory for do_show_memory_taint_map()\n");
        return NULL;
    }

    utarray_new( match_addr, &adr_icd);

    printf("Scan for pattern %s\n", pattern);

    for(i = start_addr; i < end_addr-length+1; i++)
    {
        cpu_memory_rw_debug(cpu, i, buf, length, 0);
        if(memcmp(buf, pattern, length)==0)
        {
            printf("pattern found %lx\n", i);
            utarray_push_back(match_addr, &i);
        }
    }
    return match_addr;
}



/*******************************************************************
UT_array* memfrs_scan_phymem( uint64_t start_addr, uint64_t end_addr, const char* pattern )

Scan for specific pattern in the VM's physical memory

INPUT:    uint64_t start_addr,  The start address
          uint64_t end_addr,    the end address
          const char* pattern   pattern to search, support only ascii string
OUTPUT:   UT_array*,            An UT_array that contains the address of found pattern

*******************************************************************/
UT_array* memfrs_scan_phymem( uint64_t start_addr, uint64_t end_addr, const char* pattern , int length ) {
    uint64_t i;
    UT_array *match_addr;
    if(start_addr >= end_addr){
        printf("end_addr is not less than start_addr\n");
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(length);
    if(buf == NULL){
        printf("Cannot allocate memory for memfrs_scan_phymem()\n");
        return NULL;
    }

    utarray_new( match_addr, &adr_icd);

    printf("Scan for pattern %s\n", pattern);
    for(i = start_addr; i < end_addr-length+1; i++)
    {
        cpu_physical_memory_read(i, buf, length);
        if(memcmp(buf, pattern, length)==0)
        {
            printf("pattern found %lx\n", i);
            utarray_push_back(match_addr, &i);
        }
    }
    return match_addr;
}



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
int memfrs_get_virmem_content( CPUState *cpu, uint64_t cr3, uint64_t target_addr, uint64_t target_length, uint8_t* buf)
{
    X86CPU copied_cpu;
    int ret;
    memcpy(&copied_cpu, X86_CPU(cpu), sizeof(copied_cpu));

    if(cr3 != 0)
    {
        copied_cpu.env.cr[3] = cr3;
    }

    ret = cpu_memory_rw_debug((CPUState *)&copied_cpu, target_addr, (uint8_t*)buf, target_length, 0);
    if(ret != 0){
        //printf("Fail to read virtual memory\n");
        return -1;
    }
    return 0;
}



/*******************************************************************
void hexdump(Monitor *mon, uint8_t* buf, size_t length)

Get the memory content in virtual memory

INPUT:    Monitor *mon           Monitor
          uint8_t* buf           target buffer
          size_t length          length of buffer
OUTPUT:   void
*******************************************************************/
void hexdump(Monitor *mon, uint8_t* buf, size_t length)
{
    int i,j ;

    for(i = 0 ; i < (int)length ; i+=0x10) {
        monitor_printf(mon, "%02x: ", i);
        for(j = 0; j< 0x10; j++){
            if(i+j > (int)length)
                monitor_printf( mon, "   " );
            else
                monitor_printf( mon, "%02x " , buf[i+j]);
        }

        monitor_printf(mon, "  |  ");

        for(j = 0; j< 0x10; j++){
            if(i+j > (int)length)
                monitor_printf( mon, "-" );
            else if(buf[i+j] >= 0x20 && buf[i+j] <= 0x7e)
                monitor_printf( mon, "%c" , buf[i+j]);
            else
                monitor_printf( mon, "." );
        }

        monitor_printf(mon, "|\n");
    }

}



/*******************************************************************
char* parse_unicode_strptr(uint64_t ustr_ptr, CPUState *cpu)

parse unicode string from address "ustr_ptr", this is at begining of structure _UNICODE_STRING

INPUT:    uint64_t ustr_ptr,     the begining address of structure _UNICODE_STRING
          CPUState *cpu,         the pointer to current cpu
OUTPUT:   char*                  return the ascii string
*******************************************************************/
char* parse_unicode_strptr(uint64_t ustr_ptr, CPUState *cpu)
{
    int i;
    uint64_t buf_ptr;
    uint16_t length = 0,
             max_length = 0;
    uint8_t *buf;
    char* str;

    int offset_maxlength_to_unicode,
        offset_length_to_unicode,
        offset_buffer_to_unicode;


    // Get maximum length
    memfrs_get_nested_field_offset(&offset_maxlength_to_unicode, "_UNICODE_STRING", 1, "MaximumLength");
    if( cpu_memory_rw_debug( cpu, ustr_ptr+offset_maxlength_to_unicode, (uint8_t*)&max_length, sizeof(max_length), 0 ) !=0 )
        return NULL;

    // Get length
    memfrs_get_nested_field_offset(&offset_length_to_unicode, "_UNICODE_STRING", 1, "Length");
    if( cpu_memory_rw_debug( cpu, ustr_ptr+offset_length_to_unicode, (uint8_t*)&length, sizeof(length), 0 ) != 0 )
        return NULL;

    if(length == 0 || max_length ==0)
        return NULL;


    // Get buffer
    memfrs_get_nested_field_offset(&offset_buffer_to_unicode, "_UNICODE_STRING", 1, "Buffer");
    if( cpu_memory_rw_debug( cpu, ustr_ptr+offset_buffer_to_unicode, (uint8_t*)&buf_ptr, sizeof(buf_ptr), 0 ) != 0 )
        return NULL;


    buf = (uint8_t*)malloc(max_length+2);
    str = (char*)malloc(max_length+1);
    memset(str, 0, max_length+1);
    if( cpu_memory_rw_debug( cpu, buf_ptr, buf, max_length, 0 ) !=0 )
        return NULL;
    // Hardcode Unicode Parse
    for(i=0; i<max_length;i+=2)
        str[i/2] = buf[i];
    str[i] = 0x00;

    free(buf);
    return str;
}



/*******************************************************************
char* parse_unicode_str(uint8_t* ustr, CPUState *cpu)

Get the memory content in virtual memory

INPUT:    uint64_t ustr          unicode string
          CPUState *cpu          Current cpu
OUTPUT:   char*                  ascii string
*******************************************************************/
char* parse_unicode_str(uint8_t* ustr, CPUState *cpu)
{
    json_object* justr = NULL;
    field_info* f_info = NULL;
    uint16_t length, max_length;
    uint64_t buf_ptr;
    int offset;
    uint8_t *buf;
    char* str;
    int i;

    justr = memfrs_q_struct("_UNICODE_STRING");

    f_info = memfrs_q_field(justr, "MaximumLength");
    offset = f_info->offset;
    max_length = *((uint16_t*)(ustr+offset));
    //cpu_memory_rw_debug( cpu, ustr_ptr+offset, (uint8_t*)&max_length, sizeof(max_length), 0 );
    memfrs_close_field(f_info);

    f_info = memfrs_q_field(justr, "Length");
    offset = f_info->offset;
    length = *((uint16_t*)(ustr+offset));
    //cpu_memory_rw_debug( cpu, ustr_ptr+offset, (uint8_t*)&length, sizeof(length), 0 );
    memfrs_close_field(f_info);

    if(length == 0 || length > 256 || max_length ==0 || max_length > 256)
        return NULL;

    f_info = memfrs_q_field(justr, "Buffer");
    offset = f_info->offset;
    buf_ptr = *((uint64_t*)(ustr+offset));
    memfrs_close_field(f_info);
    

    buf = (uint8_t*)malloc(max_length+2);
    str = (char*)malloc(max_length+1);
    memset(str, 0, max_length+1);
    cpu_memory_rw_debug( cpu, buf_ptr, buf, max_length, 0 );
    //Hardcode Unicode Parse
    //wcstombs(str, (const wchar_t *)buf, max_length);
    for(i=0; i<max_length;i+=2)
        str[i/2] = buf[i];
    str[i] = 0x00;

    free(buf);
    return str;
}



/*******************************************************************
int memfrs_load_structs( const char* gvar_filename)

Load the global variable information into g_globalvar_info.

INPUT:     const char* gvar_filename,  the filename of json global variable database
OUTPUT:    int,                        return 0 if sucess, and not 0 otherwise

*******************************************************************/
int memfrs_load_globalvar( const char* gvar_filename)
{
    g_globalvar_info = json_object_from_file(gvar_filename);
    return 0;
}



/*******************************************************************
json_object* memfrs_q_globalvar(const char* gvar_name)

query the global variable's info via given variable name

INPUT:    const char* gvar_name,  the name of interesting global symbol
OUTPUT:   json_object*,         json object representation of the target global var

*******************************************************************/
json_object* memfrs_q_globalvar(const char* gvar_name)
{
    json_object* target = NULL;

    if(g_globalvar_info==NULL)
        return NULL;

    // Query global structure info with structure name ds_name
    // Restore the query result into target json_object 
    json_object_object_get_ex(g_globalvar_info, gvar_name, &target);

    if(target==NULL)
        printf("%s not found\n", gvar_name);
    return target;
}



/*******************************************************************
uint64_t memfrs_gvar_offset(json_object* gvarobj)

Get the virtual address of specific global variable, which is in
json_object format. 

memfrs_q_globalvar should be invoked first to get the json_object.

INPUT:    json_object* gvarobj  the json obj of interesting global symbol
OUTPUT:   int64_t               the virtual address of specific global variable, -1 indicates fails
*******************************************************************/
int64_t memfrs_gvar_offset(json_object* gvarobj)
{
    if(gvarobj==NULL)
        return -1;
    json_object* tmp_jobject = json_object_array_get_idx(gvarobj, 0);
    uint64_t offset = json_object_get_int(tmp_jobject);
    return offset;
}



/*******************************************************************
reverse_symbol* memfrs_build_gvar_lookup_map(void)

Load global variable to reverse_symbol_table

INPUT:    void
OUTPUT:   reverse_symbol*       reverse_symbol_table
*******************************************************************/
reverse_symbol* memfrs_build_gvar_lookup_map(void)
{
    //json_object* lookup_map = NULL;
    // Check if kernel base and global var exist
    uint64_t kernel_base = memfrs_get_nt_kernel_base();
    if( kernel_base ==0 ){
        printf("Kernel not found\n");
        return NULL;
    }
    if( g_globalvar_info==NULL ){
        printf("gvar information not found\n");
        return NULL;
    }
    
    //lookup_map = json_object_new_object();
    reverse_symbol *rev_symtab = NULL; 
    json_object_object_foreach( g_globalvar_info, key, val){
        json_object* tmp_jobject = json_object_array_get_idx(val, 0);
        uint64_t offset = json_object_get_int(tmp_jobject);
        reverse_symbol* rec = (reverse_symbol*)malloc(sizeof(reverse_symbol)); 
        rec->offset = offset;
        rec->symbol = key;
        HASH_ADD_INT( rev_symtab, offset, rec ); 
    }
    return rev_symtab;
}



/*******************************************************************
char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset)

get the symbolname at specific virtual memory address from reverse_symbol_table

INPUT:    reverse_symbol* rsym_tab  reverse_symbol_table
          int offset                target address
OUTPUT:   char*                     symbol name
*******************************************************************/
char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset)
{
    reverse_symbol* sym = NULL;

    if(rsym_tab == NULL)
        return NULL;

    HASH_FIND_INT(rsym_tab, &offset, sym);

    if(sym == NULL)
        return NULL;
    return sym->symbol; 
}



/*******************************************************************
int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab)

Free reverse_symbol_table

INPUT:    reverse_symbol* rsym_tab  
          int offset                target address
OUTPUT:   int                       return 0 for success
*******************************************************************/
int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab)
{
    reverse_symbol *current_sym, *tmp;

    if(rsym_tab == NULL)
        return -1;

    HASH_ITER(hh, rsym_tab, current_sym, tmp){
        HASH_DEL(rsym_tab, current_sym);
        free(current_sym);
    }
    return 0;
}



/*******************************************************************
int memfrs_display_type(CPUState *cpu, uint64_t addr, const char* struct_name)

Fit the memory at addr into structure fields

INPUT:    CPUState *cpu             Current cpu
          uint64_t addr             address
          const char* struct_name   struct name
OUTPUT:   int                       return 0 for success
*******************************************************************/
int memfrs_display_type(CPUState *cpu, uint64_t addr, const char* struct_name)
{
    printf("%s\n", struct_name);
    json_object* jobj = memfrs_q_struct(struct_name);    
    uint8_t buf[0x30];
    char type_info[64];
    if(jobj==NULL)
        return -1;
    json_object_object_foreach(jobj, key, val){
        //printf("%s: %s\n", key, json_object_to_json_string(val));
        if( strcmp(key, "[structure_size]")==0)
            continue;
        json_object* type = json_object_array_get_idx(val, 0);
        int offset = json_object_get_int(json_object_array_get_idx(val, 1));
        int size = json_object_get_int(json_object_array_get_idx(val, 2));
  
        strncpy(type_info, key, 63);
        strncat(type_info, "(", 63);
        strncat(type_info, json_object_get_string(type), 63);
        strncat(type_info, ")", 63);

        printf("%-30s@%lx:\t", type_info, addr+offset);
        int i;
        if(size > 0x10)
        {
            printf("...\n");
            continue;
        }
        cpu_memory_rw_debug( cpu, addr+offset , buf, 0x30, 0 );
        for(i=0 ; i< size; i++)
        {
            printf("%02x ", buf[i]);
        }
        
        printf("\n");
    }
    return 0;
}



int memfrs_get_mem_struct_content(
        CPUState   *cpu,
        uint64_t    cr3,
        uint8_t    *buffer,
        int         len,
        uint64_t    struct_addr,
        bool        from_physical_memory,
        const char *struct_type_name,
        int         depth,
        ...) {
    // XXX: Now use extra char at beginning of field name to
    // indicate that the field is a pointer or not.
    // Should load and parse the structure file correctly instead.
    // XXX: assuming pointer has size of 8

    int errcode = 0;
    va_list vl;
    json_object *struct_type;
    field_info *info = NULL;
    const char *field_name;

    struct_type = memfrs_q_struct(struct_type_name);
    if (struct_type == NULL)
        return -1;

    va_start(vl, depth);

    if(from_physical_memory){

        field_name = va_arg(vl, const char*);
        info = memfrs_q_field(struct_type, field_name+1);

        if(depth==1){
            cpu_physical_memory_read(struct_addr + info->offset , buffer, len);

            free(info);
            va_end(vl);
            return 0;
        }
        else if(depth>1){
            cpu_physical_memory_read( struct_addr + info->offset , &struct_addr, 8);
            depth = depth-1;

            while(depth--) {
                struct_type = info->jobject_type;
                free(info);
                field_name = va_arg(vl, const char*);
                info = memfrs_q_field(struct_type, field_name+1);
                if (info == NULL)
                    return -1;

                if (field_name[0] == '*')
                    info->is_pointer = true;
                else
                    info->is_pointer = false;

                struct_addr += info->offset;

                if (depth!=0 && info && info->is_pointer) {
                    errcode = memfrs_get_virmem_content(cpu, cr3, struct_addr, 8, (uint8_t*)&struct_addr);
                    if (errcode == -1)
                        return -1;
                }
            }

            free(info);
            va_end(vl);
            return memfrs_get_virmem_content(cpu, cr3, struct_addr, len, buffer);
        }
        else
            return -1;
    }
    else{
        while (depth--) {
            if (info && info->is_pointer) {
                errcode = memfrs_get_virmem_content(cpu, cr3, struct_addr, 8, (uint8_t*)&struct_addr);
                if (errcode == -1)
                    return -1;
            }

            free(info);
            field_name = va_arg(vl, const char*);
            info = memfrs_q_field(struct_type, field_name+1);
            if (info == NULL)
                return -1;

            if (field_name[0] == '*')
                info->is_pointer = true;
            else
                info->is_pointer = false;

            struct_addr += info->offset;
            struct_type = info->jobject_type;
        }
        free(info);
        va_end(vl);

        return memfrs_get_virmem_content(cpu, cr3, struct_addr, len, buffer);
    }
}



int memfrs_get_nested_field_offset(int *out, const char *struct_type_name, int depth, ...) {
    json_object *struct_type;
    va_list vl;
    field_info *info = NULL;
    const char *field_name;
    int offset = 0;

    struct_type = memfrs_q_struct(struct_type_name);
    if (struct_type == NULL)
        return -1;

    va_start(vl, depth);
    // Process field query
    while (depth--) {
        field_name = va_arg(vl, const char*);
        info = memfrs_q_field(struct_type, field_name);
        if (info == NULL)
            return -1;

        struct_type = info->jobject_type;
        offset += info->offset;
        free(info);
    }
    va_end(vl);

    *out = offset;
    return 0;
}
