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



// process list destructor
static void process_list_dtor(void *_elt) {
    process_list_st *elt = (process_list_st*)_elt;
    if(elt->full_file_path) free(elt->full_file_path);
}
UT_icd proc_list_icd = {sizeof(process_list_st), NULL, NULL, process_list_dtor};



UT_array* memfrs_enum_proc_list(CPUState *cpu)
{
    // Target return structure
    UT_array *list = NULL;

    process_list_st proc_list;

    uint64_t kpcr_ptr = memfrs_get_kpcr_ptr();

    uint64_t kthread_ptr,
             eprocess_ptr,
             eprocess_ptr_init,
             buf_ptr;

    uint64_t cr3,
             processid;

    // Max length of file name is 15
    uint8_t file_name_buf[16];
    char *file_path_buf;

    int offset_entry_list_to_eprocess =0;
    int offset_image_path_name_to_RTL =0;
    int process_count = 0;

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

    // Read the concrete memory value of kthread_ptr(CurrentThread) via _KPCR address
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&kthread_ptr, sizeof(kthread_ptr), kpcr_ptr, false, "_KPCR", 2, "#Prcb", "#CurrentThread");

    // Read the concrete memory value of PROCESS via CurrentThread
    // Get the first PROCESS
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), kthread_ptr, false, "_KTHREAD", 1, "#Process");


    // Assign process_list be a 'process_list_st' structure UTarray
    utarray_new(list, &proc_list_icd);


    // Start iteration process list
    eprocess_ptr_init = eprocess_ptr;
    memfrs_get_nested_field_offset(&offset_image_path_name_to_RTL, "_RTL_USER_PROCESS_PARAMETERS", 1, "ImagePathName");
    memfrs_get_nested_field_offset(&offset_entry_list_to_eprocess, "_EPROCESS", 1, "ActiveProcessLinks");

    do {
        // Read CR3 & Process name
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&cr3, sizeof(cr3), eprocess_ptr, false, "_EPROCESS", 2, "#Pcb", "#DirectoryTableBase");
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&processid, sizeof(processid), eprocess_ptr, false, "_EPROCESS", 1, "#UniqueProcessId");
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)file_name_buf, sizeof(file_name_buf), eprocess_ptr, false, "_EPROCESS", 1, "#ImageFileName");

        // If cr3 is invalid, continue.
        if (cr3 == 0)
            continue;

        // pid may not greater than 65536
        if (processid > 65536) {
            free(list);
            memfrs_errno = MEMFRS_ERR_INVALID_EPROCESS;
            return NULL;
        }
            

        file_path_buf = NULL;
        if (memfrs_get_mem_struct_content(cpu, cr3, (uint8_t*)&buf_ptr, sizeof(buf_ptr), eprocess_ptr, false, "_EPROCESS", 2, "*Peb", "*ProcessParameters") != -1)
            file_path_buf = parse_unicode_strptr(buf_ptr + offset_image_path_name_to_RTL, cr3, cpu);


        // [TODO] Image file path sometimes will stored in unvalid address for unknow reason.
        if (file_path_buf == NULL) {
            proc_list.full_file_path = (char*)malloc(32);
            snprintf(proc_list.full_file_path, 32, "[Process Name] %-15s", file_name_buf);
        }
        else {
            proc_list.full_file_path = file_path_buf;
        }

        // Insert datas to process structure
        proc_list.eprocess = eprocess_ptr;
        proc_list.cr3 = cr3;
        proc_list.pid = processid;
        utarray_push_back(list, &proc_list);


        // Max number of process in windows is 65536.
        // Checking process count to prevent initial eprocess address error from listing process not stop.
        process_count++;
        if (process_count > 65536)
            break;

        // Read next entry
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&eprocess_ptr, sizeof(eprocess_ptr), eprocess_ptr, false, "_EPROCESS", 2, "#ActiveProcessLinks", "*Blink");
        // Substract entry_list offset to find base address of eprocess
        eprocess_ptr = eprocess_ptr - offset_entry_list_to_eprocess;

    }while (eprocess_ptr != eprocess_ptr_init);

    return list;
}
