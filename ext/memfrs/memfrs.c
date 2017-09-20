/*
 *  MBA Virtual Machine Memory Introspection implementation
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

#define dt_buf_size 0x30
#define dt_type_info_size 64



/* Global Variable */
uint64_t g_kpcr_ptr;
json_object *g_struct_info = NULL;
json_object *g_globalvar_info = NULL;

MEMFRS_ERRNO memfrs_errno;



/* Private API */



extern void hexdump(Monitor *mon, uint8_t* buf, size_t length)
{
    int i,j ;

    for (i=0 ; i<(int)length ; i+=0x10) {
        monitor_printf(mon, "%02x: ", i);
        for (j=0; j<0x10; ++j) {
            if(i+j > (int)length)
                monitor_printf( mon, "   " );
            else
                monitor_printf( mon, "%02x " , buf[i+j]);
        }

        monitor_printf(mon, "  |  ");

        for (j=0; j<0x10; ++j){
            if (i+j > (int)length)
                monitor_printf(mon, "-");
            else if (buf[i+j] >= 0x20 && buf[i+j] <= 0x7e)
                monitor_printf(mon, "%c" , buf[i+j]);
            else
                monitor_printf(mon, ".");
        }

        monitor_printf(mon, "|\n");
    }
}



extern char* parse_unicode_strptr(uint64_t ustr_ptr, uint64_t cr3, CPUState *cpu)
{
    char *str;

    int i;
    uint64_t buf_ptr;
    uint16_t length = 0,
             max_length = 0;
    uint8_t *buf;


    // Get maximum length
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&max_length, sizeof(max_length), ustr_ptr, false, "_UNICODE_STRING", 1, "#MaximumLength") == -1)
        return NULL;

    // Get length
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&length, sizeof(length), ustr_ptr, false, "_UNICODE_STRING", 1, "#Length") == -1)
        return NULL;

    if (length == 0 || max_length ==0 )
        return NULL;

    // Get buffer
    if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&buf_ptr, sizeof(buf_ptr), ustr_ptr, false, "_UNICODE_STRING", 1, "#Buffer") == -1)
        return NULL;

    buf = (uint8_t*)malloc(max_length+1);
    if (memfrs_get_virmem_content( cpu, cr3, buf_ptr, max_length, (uint8_t*)buf ) == -1) {
        free(buf);
        return NULL;
    }

    //Hardcode Unicode Parse
    str = (char*)malloc(max_length+1);
    memset(str, 0, max_length+1);
    for (i=0 ; i<max_length ; i+=2)
        str[i/2] = buf[i];   
    str[i] = '\0';

    free(buf);
    return str;
}



extern char* parse_unicode_str(uint8_t* ustr, CPUState *cpu)
{
    char *str;

    int i;
    uint64_t buf_ptr;
    uint16_t length = 0,
             max_length = 0;
    uint8_t *buf;

    int maxlength_offset_to_unicode,
        length_offset_to_unicode,
        buffer_offset_to_unicode;

    memfrs_get_nested_field_offset(&maxlength_offset_to_unicode, "_UNICODE_STRING", 1, "MaximumLength");
    memfrs_get_nested_field_offset(&length_offset_to_unicode, "_UNICODE_STRING", 1, "Length");
    memfrs_get_nested_field_offset(&buffer_offset_to_unicode, "_UNICODE_STRING", 1, "Buffer");

    max_length = *((uint16_t*)(ustr+maxlength_offset_to_unicode));
    length = *((uint16_t*)(ustr+length_offset_to_unicode));

    if (length == 0 || max_length == 0)
        return NULL;

    buf_ptr = *((uint64_t*)(ustr+buffer_offset_to_unicode));
    buf = (uint8_t*)malloc(max_length+2);
    if (cpu_memory_rw_debug(cpu, buf_ptr, buf, max_length, 0) != 0) {
        free(buf);
        return NULL;
    }

    str = (char*)malloc(max_length+1);
    memset(str, 0, max_length+1);

    //Hardcode Unicode Parse
    for (i=0 ; i<max_length ; i+=2)
        str[i/2] = buf[i];
    str[i] = '\0';

    free(buf);
    return str;
}



/* Public API */



extern bool memfrs_kpcr_self_check(uint64_t kpcr_ptr)
{
    uint64_t self_ptr = 0;
    json_object* test_obj;
    int offset_self_to_kpcr;

    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return false;
    }

    // Find the struct _KPCR
    json_object_object_get_ex(g_struct_info, "_KPCR", &test_obj);
    if (test_obj == NULL)
        return false;

    // Query field name Self in _KPCR structure
    if (memfrs_get_nested_field_offset(&offset_self_to_kpcr, "_KPCR", 1, "Self") == -1)
        return false;

    // Read the concrete memory value in Self field
    if (memfrs_get_mem_struct_content((CPUState*)current_cpu, 0, (uint8_t*)&self_ptr, sizeof(self_ptr), kpcr_ptr, false, "_KPCR", 1, "#Self") == -1) {
        g_kpcr_ptr = 0;
        return false;
    }

    // Check if the Self pointer point back to _KPCR structure, which is the hueristic check of _KPCR
    if (kpcr_ptr != 0x0 && kpcr_ptr == self_ptr) {
        return true;
    }

    g_kpcr_ptr = 0;
    return false;
}



extern void memfrs_set_kpcr_ptr(uint64_t kpcr_ptr)
{
    g_kpcr_ptr = kpcr_ptr;
}



extern uint64_t memfrs_get_kpcr_ptr(void)
{
    return g_kpcr_ptr;
}



extern json_object* memfrs_q_struct(const char* ds_name)
{
    json_object* target = NULL;

    // Query global structure info with structure name ds_name
    // Restore the query result into target json_object
    if (memfrs_check_struct_info() != 0)
        json_object_object_get_ex(g_struct_info, ds_name, &target);
    else
        return NULL;

    if (target == NULL)
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_JSON_FIELD;

    return target;
}



extern field_info* memfrs_q_field( json_object* struc, const char* field_name )
{
    json_object* target = NULL;
    json_object* tmp_jobject = NULL;
    field_info* f_info = NULL;
    int offset = 0;

    // Query the field in the structures(struc) by the field_name
    // Save the result into target json object
    json_object_object_get_ex(struc, field_name, &target);
    if (target == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_JSON_FIELD;
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
    
    if (f_info -> pointer_dereference_count > 0)
        f_info->is_pointer = true;
    else
        f_info->is_pointer = false;    

    // Put the json object of field type into fielf_info structure
    if (memfrs_check_struct_info() != 0)
        json_object_object_get_ex(g_struct_info, f_info->type_name, &(f_info->jobject_type));

    return f_info;
}



extern int memfrs_load_structs(const char* type_filename)
{
    json_object *struct_info = NULL,
                *test_obj = NULL;
    int return_value = 0;

    if (memfrs_check_struct_info() == 0) {
        g_struct_info = json_object_from_file(type_filename);
    }
    else {
        struct_info = json_object_from_file(type_filename);
        json_object_object_foreach(struct_info, key, val) {
            json_object_object_get_ex(g_struct_info, key, &test_obj);
            if (test_obj != NULL)
                ++return_value;
            json_object_object_add(g_struct_info, key, val);
        }
    }

    return return_value;
}



extern int memfrs_load_globalvar( const char* gvar_filename)
{
    json_object *struct_info = NULL,
                *test_obj = NULL;
    int return_value = 0;

    if (memfrs_check_globalvar_info() == 0) {
        g_globalvar_info = json_object_from_file(gvar_filename);
    }
    else {
        struct_info = json_object_from_file(gvar_filename);
        json_object_object_foreach(struct_info, key, val) {
            json_object_object_get_ex(g_globalvar_info, key, &test_obj);
            if (test_obj != NULL)
                ++return_value;
            json_object_object_add(g_globalvar_info, key, val);
        }
    }

    return return_value;
}



extern bool memfrs_check_struct_info(void)
{
    return (g_struct_info!=NULL)? true : false;
}



extern bool memfrs_check_globalvar_info(void)
{
    return (g_globalvar_info!=NULL)? true : false;
}



UT_icd adr_icd = {sizeof(uint64_t), NULL, NULL, NULL };
extern UT_array* memfrs_scan_virmem( CPUState *cpu, uint64_t start_addr, uint64_t end_addr, const char* pattern, int length )
{
    uint64_t i;
    UT_array *match_addr;

    if (start_addr >= end_addr) {
        memfrs_errno = MEMFRS_ERR_INVALID_MBA_MEMFRS_COMMAND;
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(length);
    memset(buf, 0, length);
    if (buf == NULL) {
        memfrs_errno = MEMFRS_ERR_ALLOC_FAILED;
        return NULL;
    }

    utarray_new(match_addr, &adr_icd);

    for (i=start_addr ; i<end_addr-length+1 ; ++i) {
        cpu_memory_rw_debug(cpu, i, buf, length, 0);
        if (memcmp(buf, pattern, length) == 0)
            utarray_push_back(match_addr, &i);
    }
    return match_addr;
}



extern UT_array* memfrs_scan_phymem(uint64_t start_addr, uint64_t end_addr, const char* pattern , int length)
{
    uint64_t i;
    UT_array *match_addr;
    if (start_addr >= end_addr) {
        memfrs_errno = MEMFRS_ERR_INVALID_MBA_MEMFRS_COMMAND;
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(length);
    memset(buf, 0, length);
    if (buf == NULL) {
        memfrs_errno = MEMFRS_ERR_ALLOC_FAILED;
        return NULL;
    }

    utarray_new( match_addr, &adr_icd);

    for (i=start_addr; i<end_addr-length+1; ++i) {
        cpu_physical_memory_read(i, buf, length);
        if (memcmp(buf, pattern, length) == 0)
            utarray_push_back(match_addr, &i);
    }
    return match_addr;
}



extern int memfrs_get_virmem_content(CPUState *cpu, uint64_t cr3, uint64_t target_addr, uint64_t target_length, uint8_t* buf)
{
    X86CPU copied_cpu;
    memcpy(&copied_cpu, X86_CPU(cpu), sizeof(copied_cpu));

    if (cr3 != 0) {
        copied_cpu.env.cr[3] = cr3;
    }

    if (cpu_memory_rw_debug((CPUState *)&copied_cpu, target_addr, (uint8_t*)buf, target_length, 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }

    return 0;
}



extern json_object* memfrs_q_globalvar(const char* gvar_name)
{
    json_object* target = NULL;

    // Check if the global data structure information is loaded
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }

    // Query global structure info with structure name ds_name
    // Restore the query result into target json_object
    json_object_object_get_ex(g_globalvar_info, gvar_name, &target);
    if (target == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE_INFO;
    }

    return target;
}



extern int64_t memfrs_gvar_offset(json_object* gvarobj)
{
    uint64_t offset;
    json_object* tmp_jobject;

    if (gvarobj == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_JSON_OBJ;
        return -1;
    }

    tmp_jobject = json_object_array_get_idx(gvarobj, 0);
    offset = json_object_get_int(tmp_jobject);
    return offset;
}



extern reverse_symbol* memfrs_build_gvar_lookup_map(void)
{
    reverse_symbol *rev_symtab = NULL;

    // Check if kernel base and global var exist
    uint64_t kernel_base = memfrs_get_nt_kernel_base();
    if (kernel_base == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KERNEL_BASE;
        return NULL;
    }
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }

    json_object_object_foreach (g_globalvar_info, key, val) {
        json_object* tmp_jobject = json_object_array_get_idx(val, 0);
        uint64_t offset = json_object_get_int(tmp_jobject);
        reverse_symbol* rec = (reverse_symbol*)malloc(sizeof(reverse_symbol));

        rec->offset = offset;
        rec->symbol = key;

        HASH_ADD_INT(rev_symtab, offset, rec);
    }

    return rev_symtab;
}



extern char* memfrs_get_symbolname_via_address(reverse_symbol* rsym_tab, int offset)
{
    reverse_symbol* sym = NULL;

    if (rsym_tab == NULL)
        return NULL;

    HASH_FIND_INT(rsym_tab, &offset, sym);

    if (sym == NULL)
        return NULL;

    return sym->symbol;
}



extern int memfrs_free_reverse_lookup_map(reverse_symbol* rsym_tab)
{
    reverse_symbol *current_sym, *tmp;

    if (rsym_tab == NULL)
        return -1;

    HASH_ITER(hh, rsym_tab, current_sym, tmp) {
        HASH_DEL(rsym_tab, current_sym);
        free(current_sym);
    }
    return 0;
}



extern float memfrs_get_windows_version(CPUState *cpu)
{
    float version;
    json_object *struct_type;
    json_object *gvar = NULL;
    field_info *info = NULL;

    uint64_t kpcr_ptr = memfrs_get_kpcr_ptr();

    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return -1.0;
    }
    //Check if the data structure information is loaded
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return -1.0;
    }

    //Check if kpcr is already found
    if (kpcr_ptr == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return -1.0;
    }

    //Check the cpu pointer valid
    if (cpu == NULL) {
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
    if ((struct_type = memfrs_q_struct("_OBJECT_HEADER")) != NULL && (info = memfrs_q_field(struct_type, "TypeIndex")) != NULL) {

        // Windows 10 introduces a cookie for object types.
        gvar = memfrs_q_globalvar("ObHeaderCookie");
        if (gvar != NULL)
            version = 10.0;

        // Windows 7
        else if ((struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot.BalancedRoot")) != NULL &&
                 (strcmp(info->type_name, "_MMADDRESS_NODE")==0))
            version = 6.1;

        // Windows 8 uses _MM_AVL_NODE as the VAD traversor struct.
        else if ((struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot")) != NULL &&
                 (strcmp(info->type_name, "_MM_AVL_TABLE")==0))
            version = 6.2;

        // Windows 8.1 and on uses _RTL_AVL_TREE
        else if ((struct_type = memfrs_q_struct("_EPROCESS")) != NULL &&
                 (info = memfrs_q_field(struct_type, "VadRoot")) != NULL &&
                 (strcmp(info->type_name, "_RTL_AVL_TREE")==0))
            version = 6.3;

        // Unknown windows version
        else
            version = 0.0;
    }

    // Windows XP did not use a BalancedRoot for VADs.
    else if ((struct_type = memfrs_q_struct("_MM_AVL_TABLE")) != NULL && (info = memfrs_q_field(struct_type, "BalancedRoot")) == NULL)
        version = 5.1;

    else
        version = 0.0;

    if(info != NULL)
        free(info);

    return version;
}



extern current_thread *memfrs_get_current_thread( CPUState *cpu)
{
    current_thread *thread_data=NULL;

    uint64_t kpcr_ptr = memfrs_get_kpcr_ptr();

    uint64_t thread_ptr,
             eprocess_ptr;
    uint64_t pid,
             tid;
    uint8_t image_file_name[16];        // Max size of image name in _EPROCESS is 16


    // Check if the data structure information is already loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }
    // Check if kpcr is already found
    if (kpcr_ptr == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return NULL;
    }
    // Check the cpu pointer is valid
    if (cpu == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return NULL;
    }


    // Get Current thread address
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&thread_ptr, sizeof(thread_ptr), kpcr_ptr, false, "_KPCR", 2, "*CurrentPrcb", "*CurrentThread");
    // Get PID and TID
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&pid, sizeof(pid), thread_ptr, false, "_ETHREAD", 2, "#Cid", "#UniqueProcess");
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&tid, sizeof(tid), thread_ptr, false, "_ETHREAD", 2, "#Cid", "#UniqueThread");

    // Get current image name
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), thread_ptr, false, "_KTHREAD", 1, "*Process");
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&image_file_name, sizeof(image_file_name), eprocess_ptr, false, "_EPROCESS", 1, "*ImageFileName");
    image_file_name[15]='\0';

    // Set values in return structure
    thread_data = (current_thread*)malloc(sizeof(current_thread));
    thread_data->tid = tid;
    thread_data->pid = pid;
    snprintf(thread_data->image_file_name, 16, "%s", image_file_name);

    return thread_data;
}



extern int memfrs_display_type(Monitor *mon, CPUState *cpu, uint64_t addr, const char* struct_name)
{
    monitor_printf(mon, "%s\n", struct_name);
    int i;
    json_object* jobj = memfrs_q_struct(struct_name);
    uint8_t buf[dt_buf_size];
    char type_info[dt_type_info_size];

    if (jobj == NULL)
        return -1;

    json_object_object_foreach(jobj, key, val){
        if (strcmp(key, "[structure_size]") == 0)
            continue;

        json_object* type = json_object_array_get_idx(val, 0);
        int offset = json_object_get_int(json_object_array_get_idx(val, 1));
        int size = json_object_get_int(json_object_array_get_idx(val, 2));
  
        strncpy(type_info, key, dt_type_info_size-1);
        strncat(type_info, "(", dt_type_info_size-1);
        strncat(type_info, json_object_get_string(type), dt_type_info_size-1);
        strncat(type_info, ")", dt_type_info_size-1);

        monitor_printf(mon, "%-30s@%lx:\t", type_info, addr+offset);
        if (size > 0x10) {
            monitor_printf(mon, "...\n");
            continue;
        }

        cpu_memory_rw_debug(cpu, addr+offset , buf, dt_buf_size, 0);
        for (i=0 ; i<size ; ++i)
            monitor_printf(mon, "%02x ", buf[i]);
        
        monitor_printf(mon, "\n");
    }

    return 0;
}



extern int memfrs_get_mem_struct_content(
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

    if (from_physical_memory) {

        field_name = va_arg(vl, const char*);
        info = memfrs_q_field(struct_type, field_name+1);

        if (depth == 1) {
            cpu_physical_memory_read(struct_addr + info->offset , buffer, len);

            free(info);
            va_end(vl);
            return 0;
        }
        else if (depth>1) {
            cpu_physical_memory_read( struct_addr + info->offset , &struct_addr, 8);
            depth = depth-1;

            while (depth--) {
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
    else {
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



extern int memfrs_get_nested_field_offset(int *out, const char *struct_type_name, int depth, ...) {
    json_object *struct_type;
    field_info *info = NULL;
    const char *field_name;
    int offset = 0;
    va_list vl;

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



extern const char* memfrs_get_last_error_message(void) {
    switch (memfrs_errno) {
        case MEMFRS_NO_ERR:
            return "There is no error.";

        case MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE:
            return "[ERROR] global structure has not been loaded.";

        case MEMFRS_ERR_NOT_LOADED_NETWORK_STRUCTURE:
            return "[ERROR] network structure has not been loaded.";

        case MEMFRS_ERR_NOT_LOADED_STRUCTURE:
            return "[ERROR] data structure has not been loaded.";

        case MEMFRS_ERR_NOT_FOUND_KPCR:
            return "[ERROR] KPCR can not be found.";

        case MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE:
            return "[ERROR] target global structure can not be found in loaded global structure.";

        case MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE_INFO:
            return "[ERROR] global structure information can not be found.";

        case MEMFRS_ERR_NOT_FOUND_WINDOWS_KERNEL:
            return "[ERROR] windows kernel can not be found.";

        case MEMFRS_ERR_NOT_FOUND_KERNEL_BASE:
            return "[ERROR] kernel base can not be found.";

        case MEMFRS_ERR_NOT_FOUND_PDB_PARSER:
            return "[ERROR] the path to PDB parser can not be found.\nPlease execute it in MBA_root/ext/memfrs/memfrs_pdbparser.";

        case MEMFRS_ERR_NOT_FOUND_JSON_FIELD:
            return "[ERROR] json field can not be found in json structure";

        case MEMFRS_ERR_ALLOC_FAILED:
            return "[ERROR] alloc memory failed.";

        case MEMFRS_ERR_MEMORY_READ_FAILED:
            return "[ERROR] CPU memory read failed.";

        case MEMFRS_ERR_INVALID_MBA_MEMFRS_COMMAND:
            return "[ERROR] invalid mba memfrs command";

        case MEMFRS_ERR_INVALID_CPU:
            return "[ERROR] invalid CPU";

        case MEMFRS_ERR_INVALID_EPROCESS:
            return "[ERROR] invalid EPROCESS.";

        case MEMFRS_ERR_INVALID_JSON_OBJ:
            return "[ERROR] invalid json object";

        case MEMFRS_ERR_COMMAND_EXECUTE_FAILED:
            return "[ERROR] command execute failed.";

        default :
            return "[ERROR] Unknow Error!";
    }
}
