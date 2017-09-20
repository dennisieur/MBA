/*
 *  MBA Kernel Module Introspection Implementation
 *
 *  Copyright (c)   2016 ChongKuan Chen
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
#endif

#include "memfrs.h"
#include "memfrs-priv.h"
#include "kmod.h"

#define SIZE_OF_POOL_HEADER 0x10


// UT array constructor of kernel_module_st
UT_icd module_icd = {sizeof(kernel_module_st), NULL, NULL, NULL };

/*******************************************************************
/// scan the whole physical memory for MmLd Module tag, and list all the module name in atdout.
///
/// \param cpu      pointer to current cpu
///
/// return a UT_array with kernel_module_st types
*******************************************************************/
UT_array* memfrs_scan_module(CPUState *cpu)
{
    UT_array *module_list;
    kernel_module_st *kmod;

    uint64_t i;
    uint8_t *module_tag;

    uint64_t virtual_addr,
             tmp_virtual_addr;
    uint64_t image_size;
    char *fullname,
         *basename;
    int offset_tag,
        offset_fullname,
        offset_basename;

    // Check if the data structure information is loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }

    memfrs_get_nested_field_offset(&offset_tag, "_POOL_HEADER", 1, "PoolTag");
    memfrs_get_nested_field_offset(&offset_fullname, "_LDR_DATA_TABLE_ENTRY", 1, "FullDllName");
    memfrs_get_nested_field_offset(&offset_basename, "_LDR_DATA_TABLE_ENTRY", 1, "BaseDllName");


    utarray_new(module_list, &module_icd);


    // scan whole physical memory
    module_tag = (uint8_t*)malloc(strlen(POOL_TAG_MODULE));
    for(i=0 ; i<MAXMEM-strlen(POOL_TAG_MODULE) ; ++i) {
        // read tag
        cpu_physical_memory_read(i, module_tag, strlen(POOL_TAG_MODULE));

        if (memcmp(module_tag, POOL_TAG_MODULE, strlen(POOL_TAG_MODULE)) == 0) {
            // #Find the first valid kernel module and find the virtual address
            // The _LDR_DATA_TABLE_ENTRY structure :
            // +0x000 InLoadOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10byts
            // +0x010 InMemoryOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes
            // +0x020 InInitializationOrderLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes
            // ......
            //
            // We can find the truly virtual address of kernel module by _LIST_ENTRY.
            // If the Flink of _LIST_ENTRY of this kernel module is the next kernel module,
            // and the Blink of _LIST_ENTRY of the next kernel module is this kernel module,
            // then we can con confirm this is a valid kernel module
            //
            // The _LIST_ENTRY structure :
            // +0x000 Flink            : Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes
            // +0x008 Blink            : Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes
            cpu_physical_memory_read(i- offset_tag+ SIZE_OF_POOL_HEADER, (uint8_t *)&virtual_addr, 8);
            if (cpu_memory_rw_debug(cpu, virtual_addr, (uint8_t*)&tmp_virtual_addr, sizeof(tmp_virtual_addr), 0) != 0)
                continue;
            if (cpu_memory_rw_debug(cpu, tmp_virtual_addr+0x8, (uint8_t*)&tmp_virtual_addr, sizeof(tmp_virtual_addr), 0) != 0)
                continue;
            if (virtual_addr == tmp_virtual_addr)
                break;
        }
    }

    if(virtual_addr != tmp_virtual_addr){
        free(module_tag);
        return module_list;
    }

    // scan every kernel module by virtual address
    do {
        // Retrieve whole path
        fullname = parse_unicode_strptr(tmp_virtual_addr + offset_fullname, 0, cpu);
        basename = parse_unicode_strptr(tmp_virtual_addr + offset_basename, 0, cpu);
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&image_size, sizeof(image_size), tmp_virtual_addr, false, "_LDR_DATA_TABLE_ENTRY", 1, "#SizeOfImage");

        if (fullname == NULL || basename == NULL || image_size == 0) {
            cpu_memory_rw_debug(cpu, tmp_virtual_addr+0x8, (uint8_t*)&tmp_virtual_addr, sizeof(tmp_virtual_addr), 0);
            continue;
        }

        // Insert datas to kernel module structure
        kmod = (kernel_module_st*)malloc(sizeof(kernel_module_st));
        kmod->virtual_addr = tmp_virtual_addr;
        kmod->image_size = image_size;
        // unicode max length is 256
        snprintf(kmod->fullname, 256, "%s", fullname);
        snprintf(kmod->basename, 256, "%s", basename);

        utarray_push_back(module_list, kmod);
        free(fullname);
        free(basename);
        free(kmod);

        cpu_memory_rw_debug(cpu, tmp_virtual_addr+0x8, (uint8_t*)&tmp_virtual_addr, sizeof(tmp_virtual_addr), 0);
    } while (tmp_virtual_addr != virtual_addr);

    free(module_tag);
    return module_list;
}
