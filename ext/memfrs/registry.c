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

#include "memfrs.h"
#include "memfrs-priv.h"
#include "registry.h"


#define copy_str_to_utarray(x)                              \
            if(x!=NULL){                                    \
                string_len = strlen(x);                     \
                hive_list.x = (char*)malloc(string_len+1);  \
                for(i=0;i<string_len;i=i+1)                 \
                    hive_list.x[i] = x[i];                  \
                hive_list.x[string_len] = '\0';             \
            }                                               \
            else{                                           \
                hive_list.x=NULL;                           \
            }
                               


static void hive_list_dtor(void *_elt) {
    hive_list_st *elt = (hive_list_st*)_elt;
    if(elt->hive_root_path) free(elt->hive_root_path);
}
UT_icd hive_list_icd = {sizeof(hive_list_st), NULL, NULL, hive_list_dtor};
/*****************************************************************n
UT_array* memfrs_enum_hive_list( uint64_t kpcr_ptr, CPUState *cpu )

Eumerate the hive file

INPUT:     uint64_t kpcr_ptr,       the address of _KPCR struct
           CPUState *cpu,           the pointer to current cpu
OUTPUT:    UT_array*                return a UT_array with hive data
*******************************************************************/
UT_array* memfrs_enum_hive_list( uint64_t kpcr_ptr, CPUState *cpu )
{
    UT_array *list = NULL;
    hive_list_st hive_list;

    int i;

    const char* hive_list_head_name = "CmpHiveListHead";
    uint64_t kernel_base = 0;
    uint64_t addr_head_CmpHiveList = 0;
    uint64_t addr_CMHIVE,
             addr_CMHIVE_HiveList;
    json_object *gvar = NULL;

    char *file_full_path,
         *file_user_name,
         *hive_root_path;
    size_t string_len;

    int offset_next_to_list_entry = 0,
        offset_HiveList_to_CMHIVE = 0,
        offset_FileFullPath_to_CMHIVE = 0,
        offset_FileUserName_to_CMHIVE = 0,
        offset_HiveRootPath_to_CMHIVE = 0;


    // Check if the data structure information is loaded
    if(g_struct_info ==NULL)
    {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }
    // Check if the global data structure information is loaded
    if(g_globalvar_info == NULL)
    {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }
    // Check if kpcr is already found
    if(kpcr_ptr == 0)
    {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return NULL;
    }
    // Check the cpu pointer valid
    if(cpu == NULL)
    {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return NULL;
    }


    // Get Name offset from _OBJECT_TYPE
    if( memfrs_get_nested_field_offset(&offset_next_to_list_entry, "_LIST_ENTRY", 1, "Flink") ==-1 )
        return NULL;
    // Get Name offset from _OBJECT_TYPE
    if( memfrs_get_nested_field_offset(&offset_HiveList_to_CMHIVE, "_CMHIVE", 1, "HiveList") ==-1 )
        return NULL;
    // Get Name offset from _OBJECT_TYPE
    if( memfrs_get_nested_field_offset(&offset_FileFullPath_to_CMHIVE, "_CMHIVE", 1, "FileFullPath") ==-1 )
        return NULL;
    // Get Name offset from _OBJECT_TYPE
    if( memfrs_get_nested_field_offset(&offset_FileUserName_to_CMHIVE, "_CMHIVE", 1, "FileUserName") ==-1 )
        return NULL;
    // Get Name offset from _OBJECT_TYPE
    if( memfrs_get_nested_field_offset(&offset_HiveRootPath_to_CMHIVE, "_CMHIVE", 1, "HiveRootPath") ==-1 )
        return NULL;


    // Kernel base
    if( (kernel_base = memfrs_get_nt_kernel_base()) == 0 &&
        (kernel_base = memfrs_find_nt_kernel_base(cpu)) ==0 ){
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KERNEL_BASE;
        return NULL;
    }

    // Get _CmpHiveListHead address
    gvar = memfrs_q_globalvar(hive_list_head_name);
    if(gvar ==NULL){
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE;
        return NULL;
    }
    else{
        addr_head_CmpHiveList = memfrs_gvar_offset(gvar) + kernel_base;
    }
    // Get _CMHIVE hive list address
    cpu_memory_rw_debug(cpu, addr_head_CmpHiveList + offset_next_to_list_entry , (uint8_t*)&addr_CMHIVE_HiveList, sizeof(addr_CMHIVE_HiveList), 0);


    utarray_new( list, &hive_list_icd);
    do{
        addr_CMHIVE = addr_CMHIVE_HiveList - offset_HiveList_to_CMHIVE;

        // Insert offset to hive structure
        hive_list.CMHIVE_address = addr_CMHIVE;

        // Insert file full path to hive structure
        file_full_path = parse_unicode_strptr(addr_CMHIVE + offset_FileFullPath_to_CMHIVE, cpu);
        copy_str_to_utarray(file_full_path);

        // Insert hive root path to hive structure
        file_user_name = parse_unicode_strptr(addr_CMHIVE + offset_FileUserName_to_CMHIVE, cpu);
        copy_str_to_utarray(file_user_name);

        // Insert hive root path to hive structure
        hive_root_path = parse_unicode_strptr(addr_CMHIVE + offset_HiveRootPath_to_CMHIVE, cpu);
        copy_str_to_utarray(hive_root_path);

        // Add datas to utarray
        utarray_push_back(list, &hive_list);

        cpu_memory_rw_debug(cpu, addr_CMHIVE_HiveList + offset_next_to_list_entry , (uint8_t*)&addr_CMHIVE_HiveList, sizeof(addr_CMHIVE_HiveList), 0);
    }while(addr_CMHIVE_HiveList != addr_head_CmpHiveList);


    return list;
}
