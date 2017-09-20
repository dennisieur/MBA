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

int registry_dumping = 0;

// [TODO] Still not know why there is storage[1] in hhive
//        storage index does not use in this file, but we keep it.
#define INDEX_STORAGE 0

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
    if (elt->hive_root_path) free(elt->hive_root_path);
}
UT_icd hive_list_icd = {sizeof(hive_list_st), NULL, NULL, hive_list_dtor};



extern UT_array* memfrs_enum_hive_list(CPUState *cpu)
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

    int offset_HiveList_to_CMHIVE = 0,
        offset_FileFullPath_to_CMHIVE = 0,
        offset_FileUserName_to_CMHIVE = 0,
        offset_HiveRootPath_to_CMHIVE = 0;


    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() ==0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }
    // Check if the global data structure information is loaded
    if (memfrs_check_globalvar_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_GLOBAL_STRUCTURE;
        return NULL;
    }
    // Check the cpu pointer valid
    if (cpu == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return NULL;
    }


    // Get HiveList offset from _CMHIVE
    if (memfrs_get_nested_field_offset(&offset_HiveList_to_CMHIVE, "_CMHIVE", 1, "HiveList") == -1)
        return NULL;
    // Get FileFullPath offset from _CMHIVE
    if (memfrs_get_nested_field_offset(&offset_FileFullPath_to_CMHIVE, "_CMHIVE", 1, "FileFullPath") == -1)
        return NULL;
    // Get FileUserName offset from _CMHIVE
    if (memfrs_get_nested_field_offset(&offset_FileUserName_to_CMHIVE, "_CMHIVE", 1, "FileUserName") == -1)
        return NULL;
    // Get HiveRootPath offset from _CMHIVE
    if (memfrs_get_nested_field_offset(&offset_HiveRootPath_to_CMHIVE, "_CMHIVE", 1, "HiveRootPath") == -1)
        return NULL;


    // Kernel base
    if (
        (kernel_base = memfrs_get_nt_kernel_base()) == 0 &&
        (kernel_base = memfrs_find_nt_kernel_base(cpu)) == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KERNEL_BASE;
        return NULL;
    }

    // Get _CmpHiveListHead address
    gvar = memfrs_q_globalvar(hive_list_head_name);
    if (gvar ==NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE;
        return NULL;
    }
    else {
        addr_head_CmpHiveList = memfrs_gvar_offset(gvar) + kernel_base;
    }
    // Get _CMHIVE hive list address
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr_CMHIVE_HiveList, sizeof(addr_CMHIVE_HiveList), addr_head_CmpHiveList, false, "_LIST_ENTRY", 1, "*Flink");


    utarray_new(list, &hive_list_icd);
    do {
        // Get new _CMHIVE address
        addr_CMHIVE = addr_CMHIVE_HiveList - offset_HiveList_to_CMHIVE;

        // Insert offset to hive structure
        hive_list.CMHIVE_address = addr_CMHIVE;

        // Insert file full path to hive structure
        file_full_path = parse_unicode_strptr(addr_CMHIVE + offset_FileFullPath_to_CMHIVE, 0, cpu);
        copy_str_to_utarray(file_full_path);

        // Insert hive root path to hive structure
        file_user_name = parse_unicode_strptr(addr_CMHIVE + offset_FileUserName_to_CMHIVE, 0, cpu);
        copy_str_to_utarray(file_user_name);

        // Insert hive root path to hive structure
        hive_root_path = parse_unicode_strptr(addr_CMHIVE + offset_HiveRootPath_to_CMHIVE, 0, cpu);
        copy_str_to_utarray(hive_root_path);

        // Add datas to utarray
        utarray_push_back(list, &hive_list);

        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr_CMHIVE_HiveList, sizeof(addr_CMHIVE_HiveList), addr_CMHIVE_HiveList, false, "_LIST_ENTRY", 1, "*Flink");
    } while (addr_CMHIVE_HiveList != addr_head_CmpHiveList);


    return list;
}



// [TODO] Need to print warnning message in another way instead for printing at here
extern int memfrs_registry_dump(CPUState *cpu, FILE *fd, uint64_t CMHIVE_address)
{
    uint64_t total_size;
    int print_loop;
    int index_directory = 0,
        index_table = 0;
    char block_buffer[BLOCK_SIZE];

    int flat;
    int read_times;
    uint64_t addr_hhive;
    uint64_t addr_base_block;
    uint64_t addr_hhive_storage,
             addr_storage_map,
             addr_map_directory,
             addr_hbin,
             last_addr_hbin;
    uint32_t total_length,
             length;
    uint32_t size_hbin;

    int offset_HHIVE_to_CMHIVE,
        offset_storage_to_HHIVE,
        offset_hbin_addr_to_table,
        offset_size_to_HBIN;

    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() ==0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return -1;
    }
    // Check the cpu pointer valid
    if (cpu == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_CPU;
        return -1;
    }


    // Get BaseBlock offset from _HHIVE
    if (memfrs_get_nested_field_offset(&offset_HHIVE_to_CMHIVE, "_CMHIVE", 1, "Hive") == -1)
        return -1;
    // Get BaseBlock offset from _HHIVE
    if (memfrs_get_nested_field_offset(&offset_storage_to_HHIVE, "_HHIVE", 1, "Storage") == -1)
        return -1;
    // Get Map hbin address from _HMAP_ENTRY
    if (memfrs_get_nested_field_offset(&offset_hbin_addr_to_table, "_HMAP_ENTRY", 1, "PermanentBinAddress") == -1)
        return -1;
    // Get Map hbin size from _HBIN
    if (memfrs_get_nested_field_offset(&offset_size_to_HBIN, "_HBIN", 1, "Size") == -1)
        return -1;


    addr_hhive = CMHIVE_address + offset_HHIVE_to_CMHIVE;

    registry_dumping = 1;


    // baseblock
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr_base_block, sizeof(addr_base_block), addr_hhive, false, "_HHIVE", 1, "*BaseBlock");
    if (cpu_memory_rw_debug(cpu, addr_base_block , (uint8_t*)&block_buffer, BLOCK_SIZE, 0) != 0) {
        printf("Physical layer returned None for basicblock\n");
        for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
            fprintf(fd, "%c", '\0');
    }
    else {
        for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
            fprintf(fd, "%c", block_buffer[print_loop]);
    }

    total_size = BLOCK_SIZE;

    addr_hhive_storage = addr_hhive + offset_storage_to_HHIVE + SIZE_Storage*INDEX_STORAGE;
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&total_length, sizeof(total_length), addr_hhive_storage, false, "_DUAL", 1, "#Length");


    // If the hive is listed as "flat", it is all contiguous in memory
    // so we can just calculate it relative to the base block.
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&flat, 0x1, addr_hhive, false, "_HHIVE", 1, "#Flat");
    flat = flat &0x1;
    if (flat == 1) {
        addr_hbin = addr_base_block + BLOCK_SIZE; 
        for (length = 0 ; length < total_length ; length += BLOCK_SIZE) {
            if (cpu_memory_rw_debug(cpu, addr_hbin, (uint8_t*)&block_buffer, BLOCK_SIZE, 0) != 0) {
                printf("Physical layer returned None for HBIN(%"PRIx64") : storage[%d] directory[%d] table[%d]\n",
                                                                addr_hbin, INDEX_STORAGE, index_directory, index_table);
                for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
                    fprintf(fd, "%c", '\0');
            }
            else {
                for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
                    fprintf(fd, "%c", block_buffer[print_loop]);
            }

            addr_hbin += BLOCK_SIZE;
            total_size += BLOCK_SIZE;
        }
    }
    else {
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&addr_storage_map, sizeof(addr_storage_map), addr_hhive_storage, false, "_DUAL", 1, "*Map");
        read_times = 0;
        last_addr_hbin = 0;
        for (length = 0 ; length < total_length ; length += BLOCK_SIZE) {
            if (cpu_memory_rw_debug(cpu, addr_storage_map + 0x8*index_directory, (uint8_t*)&addr_map_directory, sizeof(addr_map_directory), 0) != 0) {
                printf("Physical layer returned None for MAP(%"PRIx64") : storage[%d] directory[%d]\n",
                                                        addr_storage_map, INDEX_STORAGE, index_directory);
                break;
            }
            if (cpu_memory_rw_debug(cpu, addr_map_directory + SIZE_HMAP_TABLE*index_table + offset_hbin_addr_to_table, (uint8_t*)&addr_hbin, sizeof(addr_hbin), 0) != 0) {
                printf("Physical layer returned None for DIRECTORY(%"PRIx64") : storage[%d] directory[%d] table[%d]\n",
                                                            addr_map_directory, INDEX_STORAGE, index_directory, index_table);
                addr_hbin = 0x0000000000000000;
            }

            // Hbin address has unknown data in last byte
            addr_hbin = addr_hbin & 0xfffffffffffffff0;

            if (addr_hbin == last_addr_hbin)
                read_times += 1;
            else
                read_times = 0;
            last_addr_hbin = addr_hbin;

            // hbin
            // [XXX] Still need to check why hbin is empty?
            if (
                ( cpu_memory_rw_debug(cpu, addr_hbin + BLOCK_SIZE*read_times + offset_size_to_HBIN, (uint8_t*)&size_hbin, sizeof(size_hbin), 0) != 0
                  || (read_times == 0 && size_hbin == 0x0)
                )
                || cpu_memory_rw_debug(cpu, addr_hbin + BLOCK_SIZE*read_times, (uint8_t*)&block_buffer, BLOCK_SIZE, 0) != 0
            ) {
                printf("Physical layer returned None for HBIN(%"PRIx64") : storage[%d] directory[%d] table[%d]\n",
                                                                addr_hbin + BLOCK_SIZE*read_times, INDEX_STORAGE, index_directory, index_table);
                for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
                    fprintf(fd, "%c", '\0');
            }
            else {
                for (print_loop=0 ; print_loop<BLOCK_SIZE ; ++print_loop)
                    fprintf(fd, "%c", block_buffer[print_loop]);
            }

            // Add index
            index_directory += (index_table + 1)/MAX_TABLE_SIZE;
            index_table = (index_table + 1)%MAX_TABLE_SIZE;

            total_size += BLOCK_SIZE;
        }
    }

    registry_dumping = 0;
    return total_size;
}
