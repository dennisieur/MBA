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


#define ARGUMENT_ON_STACK_MASK 0xf


// ssdt list icd
UT_icd ssdt_list_icd = {sizeof(ssdt_list_st), NULL, NULL, NULL};



UT_array* memfrs_enum_ssdt_list( CPUState *cpu )
{
    UT_array *list = NULL;
    ssdt_list_st ssdt_list;

    int i;

    const char* syscall_table_name = "KiServiceTable";
    const char* syscall_count_name = "KiServiceLimit";
    uint64_t kernel_base = 0;
    uint64_t addr_KiServiceTable = 0;
    uint64_t addr_KiServiceLimit = 0;
    json_object *gvar = NULL;

    uint64_t syscall_addr;
    uint16_t syscall_count;
    int32_t  syscall_tmp_addr;
    char    *syscall_name;
    int      argnum_on_stack;

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


    // Kernel kernel_base
    if ( 
        (kernel_base = memfrs_get_nt_kernel_base()) == 0
    &&  (kernel_base = memfrs_find_nt_kernel_base(cpu)) == 0
    ) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_KERNEL_BASE;
        return NULL;
    }


    // Get syetem call table address
    gvar = memfrs_q_globalvar(syscall_table_name);
    if (gvar == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE;
        return NULL;
    }
    else {
        addr_KiServiceTable = memfrs_gvar_offset(gvar) + kernel_base;
    }

    // Get syetem call count address
    gvar = memfrs_q_globalvar(syscall_count_name);
    if (gvar == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_GLOBAL_STRUCTURE;
        return NULL;
    }
    else {
        addr_KiServiceLimit = memfrs_gvar_offset(gvar) + kernel_base;
    }

    // Get system call count
    if (cpu_memory_rw_debug(cpu, addr_KiServiceLimit, (uint8_t*)&syscall_count, sizeof(syscall_count), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return NULL;
    }


    utarray_new(list, &ssdt_list_icd);

    for (i=0 ; i<syscall_count ; ++i) {
        // A system call record in KiServiceTable is occupied 4 bytes.
        // The first 28 bits of a system call record is used for a system call address offset to kernel base.
        // The bottom 4 bits of a system call record is used for a system call argument number on stack.
        if (cpu_memory_rw_debug(cpu, addr_KiServiceTable + i*0x4 , (uint8_t*)&syscall_tmp_addr, sizeof(syscall_tmp_addr), 0) == 0) {
            syscall_addr = (syscall_tmp_addr>>4) + addr_KiServiceTable;
            argnum_on_stack = syscall_tmp_addr & ARGUMENT_ON_STACK_MASK;

            // Get system call name
            reverse_symbol* sym_rev_hash = NULL;
            sym_rev_hash = memfrs_build_gvar_lookup_map();
            syscall_name = memfrs_get_symbolname_via_address(sym_rev_hash, syscall_addr - kernel_base);
            memfrs_free_reverse_lookup_map(sym_rev_hash);

            // Insert datas to ssdt structure
            ssdt_list.index = i;
            ssdt_list.address = syscall_addr;
            ssdt_list.argnum_on_stack = argnum_on_stack;
            // system call name might not longer than 128
            snprintf(ssdt_list.system_call_name, 64, "%s", syscall_name);
            ssdt_list.system_call_name[strlen(syscall_name)] = '\0';

            // Add datas to utarray
            utarray_push_back(list, &ssdt_list);
        }
    }

    return list;
}
