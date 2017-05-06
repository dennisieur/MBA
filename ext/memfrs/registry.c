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


    // Get Next address offset from _LIST_ENTRY
    if( memfrs_get_nested_field_offset(&offset_next_to_list_entry, "_LIST_ENTRY", 1, "Flink") ==-1 )
        return NULL;
    // Get HiveList offset from _CMHIVE
    if( memfrs_get_nested_field_offset(&offset_HiveList_to_CMHIVE, "_CMHIVE", 1, "HiveList") ==-1 )
        return NULL;
    // Get FileFullPath offset from _CMHIVE
    if( memfrs_get_nested_field_offset(&offset_FileFullPath_to_CMHIVE, "_CMHIVE", 1, "FileFullPath") ==-1 )
        return NULL;
    // Get FileUserName offset from _CMHIVE
    if( memfrs_get_nested_field_offset(&offset_FileUserName_to_CMHIVE, "_CMHIVE", 1, "FileUserName") ==-1 )
        return NULL;
    // Get HiveRootPath offset from _CMHIVE
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




/*****************************************************************n
int memfrs_registry_dump( uint64_t kpcr_ptr, CPUState *cpu, FILE*fd, uint64_t CMHIVE_address )

Dump target hive file to a file.

INPUT:      uint64_t kpcr_ptr,       the address of _KPCR struct
            CPUState *cpu,           the pointer to current cpu
            FILE *fd                 the file discriptor
            uint64_t CMHIVE_address  the target hive file head address
OUTPUT:     return total size for success (the size is greater than zero)
            return -1 for error
*******************************************************************/
int memfrs_registry_dump( uint64_t kpcr_ptr, CPUState *cpu, FILE *fd, uint64_t CMHIVE_address )
{
    uint64_t total_size;
    int print_loop;
    int index_storage,
        index_directory,
        index_table,
        index_hbin_block;
    char block_buffer[4096];

    int flat;
    uint64_t addr_hhive;
    uint64_t addr_base_block;
    uint64_t addr_hhive_storage,
             addr_storage_map,
             addr_map_directory,
             addr_hbin;
    uint32_t total_length,
             length;
    uint32_t size_hbin;
    int block_number;

    int offset_HHIVE_to_CMHIVE,
        offset_flat_to_HHIVE,
        offset_baseblock_to_HHIVE,
        offset_storage_to_HHIVE,
        offset_length_to_storage,
        offset_map_to_storage,
        offset_hbina_ddr_to_table;

    // Check if the data structure information is loaded
    if(g_struct_info ==NULL)
    {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return -1;
    }
    // Check if kpcr is already found
    if(kpcr_ptr == 0)
    {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KPCR;
        return -1;
    }
    // Check the cpu pointer valid
    if(cpu == NULL)
    {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return -1;
    }


    // Get BaseBlock offset from _HHIVE
    if( memfrs_get_nested_field_offset(&offset_HHIVE_to_CMHIVE, "_CMHIVE", 1, "Hive") ==-1 )
        return -1;
    // Get BaseBlock offset from _HHIVE
    if( memfrs_get_nested_field_offset(&offset_flat_to_HHIVE, "_HHIVE", 1, "Flat") ==-1 )
        return -1;
    // Get BaseBlock offset from _HHIVE
    if( memfrs_get_nested_field_offset(&offset_baseblock_to_HHIVE, "_HHIVE", 1, "BaseBlock") ==-1 )
        return -1;
    // Get BaseBlock offset from _HHIVE
    if( memfrs_get_nested_field_offset(&offset_storage_to_HHIVE, "_HHIVE", 1, "Storage") ==-1 )
        return -1;
    // Get Length offset from storage
    if( memfrs_get_nested_field_offset(&offset_length_to_storage, "_DUAL", 1, "Length") ==-1 )
        return -1;
    // Get Map offset from storage
    if( memfrs_get_nested_field_offset(&offset_map_to_storage, "_DUAL", 1, "Map") ==-1 )
        return -1;
    // Get Map hbin address from _HMAP_ENTRY
    if( memfrs_get_nested_field_offset(&offset_hbina_ddr_to_table, "_HMAP_ENTRY", 1, "PermanentBinAddress") ==-1 )
        return -1;


    addr_hhive = CMHIVE_address + offset_HHIVE_to_CMHIVE;


    // [TODO] What means 'flat'?
    cpu_memory_rw_debug(cpu, addr_hhive + offset_flat_to_HHIVE, (uint8_t*)&flat, 0x1, 0);
    flat = flat &0x1;
    if(flat==1)
        printf("Flat = 1\n");


    // baseblock
    // [XXX] Still need to check why memory cannot accessed?
    cpu_memory_rw_debug(cpu, addr_hhive+offset_baseblock_to_HHIVE, (uint8_t*)&addr_base_block, sizeof(addr_base_block), 0);
    if( cpu_memory_rw_debug(cpu, addr_base_block , (uint8_t*)&block_buffer, BLOCK_SIZE, 0) !=0 ){
        printf("Physical layer returned None for basicblock\n");
        for(print_loop=0; print_loop<BLOCK_SIZE; print_loop=print_loop+1)
            fprintf(fd, "%c", '\0');
    }
    else{
        for(print_loop=0; print_loop<BLOCK_SIZE; print_loop=print_loop+1)
            fprintf(fd, "%c", block_buffer[print_loop]);
    }

    total_size = BLOCK_SIZE;

    // hbin
    // [XXX] Still need to check why memory cannot accessed?
    for(index_storage=0; index_storage<2; index_storage = index_storage+1){
        addr_hhive_storage = CMHIVE_address + offset_storage_to_HHIVE + SIZE_Storage*index_storage;
        cpu_memory_rw_debug(cpu, addr_hhive_storage + offset_length_to_storage, (uint8_t*)&total_length, sizeof(total_length), 0);
        cpu_memory_rw_debug(cpu, addr_hhive_storage + offset_map_to_storage, (uint8_t*)&addr_storage_map, sizeof(addr_storage_map), 0);

        total_size = total_size + total_length;

        length = 0;
        index_directory=0;
        index_table=0;
        while( length < total_length ){
            if( cpu_memory_rw_debug(cpu, addr_storage_map + 0x8*index_directory, (uint8_t*)&addr_map_directory, sizeof(addr_map_directory), 0) !=0){
                printf("Physical layer returned None for MAP(%"PRIx64") : storage[%d] directory[%d]\n", addr_storage_map, index_storage, index_directory);
                total_size = total_size - total_length;
                break;
            }
            if( cpu_memory_rw_debug(cpu, addr_map_directory + SIZE_HMAP_TABLE*index_table + offset_hbina_ddr_to_table, (uint8_t*)&addr_hbin, sizeof(addr_hbin), 0) !=0){
                printf("Physical layer returned None for DIRECTORY(%"PRIx64") : directory[%d] table[%d]\n", addr_map_directory, index_directory, index_table);
                addr_hbin = 0x0000000000000000;
            }

            // sometimes hbin address has unknown data in last byte
            addr_hbin = addr_hbin & 0xfffffffffffffff0;

            if( cpu_memory_rw_debug(cpu, addr_hbin+0x8, (uint8_t*)&size_hbin, sizeof(size_hbin), 0) != 0){
                if(addr_hbin != 0x0000000000000000)
                    printf("Physical layer returned None for HBIN(%"PRIx64") : directory[%d] table[%d]\n", addr_hbin, index_directory, index_table);
                size_hbin = BLOCK_SIZE;
                block_number = 1;
                for(print_loop=0; print_loop<BLOCK_SIZE; print_loop=print_loop+1)
                    fprintf(fd, "%c", '\0');
            }
            else{
                block_number = size_hbin/BLOCK_SIZE;
                for(index_hbin_block=0; index_hbin_block<block_number; index_hbin_block = index_hbin_block+1){
                    cpu_memory_rw_debug(cpu, addr_hbin + BLOCK_SIZE*index_hbin_block, (uint8_t*)&block_buffer, BLOCK_SIZE, 0);
                    for(print_loop=0; print_loop<BLOCK_SIZE; print_loop=print_loop+1)
                        fprintf(fd, "%c", block_buffer[print_loop]);
                }
            }

            // Add index
            index_directory = index_directory + (index_table + block_number)/MAX_TABLE_SIZE;
            index_table = (index_table + block_number)%MAX_TABLE_SIZE;
            // Add printed length
            length = length + size_hbin;
        }
    }
    return total_size;
}
