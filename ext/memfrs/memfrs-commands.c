/*
 *  MBA Virtual Machine Memory Forensic qemu command implementation
 *
 *  Copyright (c)   2012 Chiwei Wang
 *                  2016 Chiawei Wang
 *                  2016 Chongkuan Chen
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

#include "qemu-common.h"
#include "monitor/monitor.h"

#include "exec/cpu-all.h"

#include "ext/memfrs/memfrs-commands.h"
#include "ext/memfrs/memfrs.h"
#include "ext/memfrs/memfrs-priv.h"
#include "ext/memfrs/kernel.h"
#include "ext/memfrs/vad.h"
#include "ext/memfrs/kmod.h"
#include "ext/memfrs/handles.h"
#include "ext/memfrs/netscan.h"
#include "ext/memfrs/registry.h"

#include "qmp-commands.h"



/******************************************************************
* PURPOSE : Scan for the kernel base
******************************************************************/
void do_scan_kernel(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    uint64_t base;

    if ((base = memfrs_get_nt_kernel_base()) != 0) {
        monitor_printf(mon, "Kernel already find at %"PRIx64"\n", base); 
        return;
    }

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    if ((base = memfrs_find_nt_kernel_base(thiscpu)) != 0)
        monitor_printf(mon, "Kernel found %"PRIx64"\n", base);
    else
        monitor_printf(mon, "Kernel not found\n");
    return;
}



/*************************************************************************
* PURPOSE : Generate PDB's global var and structure info into profiles_dir
*************************************************************************/
void do_gen_pdb_profiles(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    const char* profile_dir = qdict_get_str(qdict, "profiles_dir");
    uint64_t base;

    // Check kernel info
    if (memfrs_get_nt_kernel_base() == 0){
        monitor_printf(mon, "No kernel information available, scan the kernel first...\n");
        return;
    }

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    if ((base = memfrs_find_nt_kernel_base(thiscpu)) != 0)
        monitor_printf(mon, "Kernel found %"PRIx64"\n", base);
    else
        monitor_printf(mon, "Kernel not found\n");

    if (memfrs_gen_pdb_profiles(profile_dir) == -1)
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());

    return;
}



/******************************************************************
* PURPOSE : Load the data structure's information into
            g_struct_info from json file of sdb_path
******************************************************************/
void do_load_structures(Monitor *mon, const QDict *qdict)
{
    int overwritten_num;
    const char* sdb_path = qdict_get_str(qdict, "sdb");
    overwritten_num = memfrs_load_structs(sdb_path);
    if (overwritten_num > 0)
        monitor_printf(mon, "%d structure fields have been overwritten.\n", overwritten_num);
    return;
}



/******************************************************************
* PURPOSE : Load the global variable's(symbols) information into
            g_globalvar_info from json file of gvar_db
******************************************************************/
void do_load_global_variable(Monitor *mon, const QDict *qdict)
{
    int overwritten_num;
    const char* gvar_path = qdict_get_str(qdict, "gvar_db");
    overwritten_num = memfrs_load_globalvar(gvar_path);;
    if (overwritten_num > 0)
        monitor_printf(mon, "%d structure fields have been overwritten.\n", overwritten_num);
    return;
}



/******************************************************************
* PURPOSE : Scan the virmem for the specific pattern
******************************************************************/
// [TODO] Fix it, possible cr3 problem
void do_scan_virmem(Monitor *mon, const QDict *qdict)
{
    UT_array *match_addr;
    CPUState *thiscpu = NULL;
    uint64_t *p;
    uint64_t start_addr = qdict_get_int(qdict, "start");
    uint64_t end_addr = qdict_get_int(qdict, "end");
    const char* pattern = qdict_get_str(qdict, "pattern");

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    match_addr = memfrs_scan_virmem(thiscpu, start_addr, end_addr, pattern, strlen(pattern));

    if (match_addr != NULL) {
        monitor_printf(mon, "%p\n", match_addr);
        for (p = (uint64_t*)utarray_front(match_addr) ; p!=NULL ; p = (uint64_t*)utarray_next(match_addr, p))
            monitor_printf(mon, "%"PRIx64"\n", *p);
        utarray_free(match_addr);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
    return;
}



/******************************************************************
* PURPOSE : Scan the Physical for the specific pattern
******************************************************************/
void do_scan_phymem(Monitor *mon, const QDict *qdict)
{
    UT_array *match_addr;
    uint64_t *p;
    uint64_t start_addr = qdict_get_int(qdict, "start");
    uint64_t end_addr = qdict_get_int(qdict, "end");
    const char* pattern = qdict_get_str(qdict, "pattern");

    match_addr = memfrs_scan_phymem(start_addr, end_addr, pattern, strlen(pattern));   

    if (match_addr != NULL) {
        for (p = (uint64_t*)utarray_front(match_addr) ; p!=NULL; p=(uint64_t*)utarray_next(match_addr, p))
            monitor_printf(mon, "%"PRIx64"\n", *p);
        utarray_free(match_addr);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
    return;
}



/*****************************************************************************
* PURPOSE : Show the virtual memory content starting at <addr> with length <len>
*****************************************************************************/
void do_show_virmem_content(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    uint64_t target_cr3	= 0;
    uint64_t target_addr = qdict_get_int(qdict, "addr");
    uint64_t target_length = qdict_get_int(qdict, "len");
    uint8_t* buf;

    if (qdict_haskey(qdict, "cr3"))
        target_cr3 = qdict_get_int(qdict, "cr3");

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    buf = (uint8_t*)malloc(target_length);
    if (buf == NULL) {
        monitor_printf(mon, "Cannot allocate memory for do_show_memory_taint_map()\n");
        return;
    }

    memset(buf, 0x00, target_length);

    memfrs_get_virmem_content(thiscpu, target_cr3, target_addr, target_length, buf);
    hexdump(mon, buf, target_length);
    free(buf);
    return;
}



/*****************************************************************************
* PURPOSE : Show the physical mem content starting at <addr> with length <len>
*****************************************************************************/
void do_show_phymem_content(Monitor *mon, const QDict *qdict)
{
    uint64_t target_addr = qdict_get_int(qdict, "addr");
    uint64_t target_length = qdict_get_int(qdict, "len");
    uint8_t* buf;

    buf = (uint8_t*)malloc(target_length);
    if (buf == NULL) {
        monitor_printf(mon, "Cannot allocate memory for do_show_memory_taint_map()\n");
        return;
    }

    monitor_printf(mon, "Display memory content %"PRIx64" to %"PRIx64"\n", target_addr, target_addr+target_length);
    cpu_physical_memory_read(target_addr, buf, target_length);
    hexdump(mon, buf, target_length);
    free(buf);
    return;
}



/******************************************************************
* PURPOSE : Get the virtual memory address of symbols with name gvar  
******************************************************************/
void do_get_gvar_vmem(Monitor *mon, const QDict *qdict)
{
    const char* name = qdict_get_str(qdict, "gvar");
    CPUState *thiscpu=NULL;
    uint64_t base = 0;
    json_object *gvar = NULL;

    if ((base = memfrs_get_nt_kernel_base()) != 0) {
        monitor_printf(mon, "Kernel already find at %"PRIx64"\n", base);
    }
    else {
        thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

        base = memfrs_find_nt_kernel_base(thiscpu);
        if ((base = memfrs_find_nt_kernel_base(thiscpu)) != 0) {
            monitor_printf(mon, "Kernel find at %"PRIx64"\n", base);
        }
        else {
            monitor_printf(mon, "Kernel not found\n");
            return;
        }
    }

    gvar = memfrs_q_globalvar(name);
    if (gvar != NULL)
        monitor_printf(mon, "%s @ 0x%"PRIx64"\n", name, memfrs_gvar_offset(gvar) + base);
    else
        monitor_printf(mon, "global structure info not found\n");

    return; 
}



/******************************************************************
* PURPOSE : Get the symbol name at specific virtual memory address
******************************************************************/
void do_get_gvar_name(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    reverse_symbol* sym_rev_hash = NULL;
    uint64_t addr = qdict_get_int(qdict, "addr");
    uint64_t ker_base;
    char* name = NULL;

    if ((ker_base = memfrs_get_nt_kernel_base()) == 0) {
        thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());
        ker_base = memfrs_find_nt_kernel_base(thiscpu);
    }

    if ((sym_rev_hash = memfrs_build_gvar_lookup_map()) != NULL) {
        if (addr > 0xffff000000000000)
            name = memfrs_get_symbolname_via_address(sym_rev_hash, addr-ker_base);
        else
            name = memfrs_get_symbolname_via_address(sym_rev_hash, addr);

        if (name) {
            monitor_printf(mon, "%s\n", name);
            memfrs_free_reverse_lookup_map(sym_rev_hash);
        }
        else
            monitor_printf(mon, "Symbol not found\n");
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());

    return ;
}



/*********************************************************************************
* PURPOSE : Get the physic address of a given virtual address in memory space(cr3)
*********************************************************************************/
void do_get_physic_address(Monitor *mon, const struct QDict *qdict)
{
    CPUState *thiscpu = NULL;
    uint64_t target_addr = qdict_get_int(qdict, "addr");
    hwaddr page = target_addr & TARGET_PAGE_MASK;

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    hwaddr phys_page = cpu_get_phys_page_debug(thiscpu, page);
    if (phys_page == -1) {
        monitor_printf(mon, "Cannot find physic page\n");
        return;
    }

    hwaddr phys_addr = phys_page + (target_addr & ~TARGET_PAGE_MASK);
    monitor_printf(mon, "physic address = %p\n", (void*)phys_addr);
    return;
}



/******************************************************************
* PURPOSE : Get windows version
******************************************************************/
void do_get_windows_version(Monitor *mon, const QDict *qdict)
{
    float version;
    CPUState *thiscpu = NULL;

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    version = memfrs_get_windows_version(thiscpu);
    if (version == -1.0)
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
    else if (version == 0.0)
        monitor_printf(mon, "Unknown Windows version\n");
    else if (version == 10.0)
        monitor_printf(mon, "Suggested Profile(s) : Windows 10, Windows Server 2016\n");
    else if (version == 6.3)
        monitor_printf(mon, "Suggested Profile(s) : Windows 8.1, Windows Server 2012 R2\n");
    else if (version == 6.2)
        monitor_printf(mon, "Suggested Profile(s) : Windows 8, Windows Server 2012\n");
    else if (version == 6.1)
        monitor_printf(mon, "Suggested Profile(s) : Windows 7, Windows Server 2008 R2\n");
    else if (version == 6.0)
        monitor_printf(mon, "Suggested Profile(s) : Windows Server 2008, Windows Vista\n");
    else if (version == 5.2)
        monitor_printf(mon, "Suggested Profile(s) : Windows Server 2003 R2, Windows Server 2003, Windows XP 64-Bit Edition\n");
    else if (version == 5.1)
        monitor_printf(mon, "Suggested Profile(s) : Windows XP\n");
    else if (version == 5.0)
        monitor_printf(mon, "Suggested Profile(s) : Windows 2000\n");
    else
        monitor_printf(mon, "Unknown Windows version\n");
}



/******************************************************************
* PURPOSE : List the running process
******************************************************************/
void do_list_process(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    UT_array *proc_list;
    process_list_st *print_proc_list;

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    proc_list = memfrs_enum_proc_list(thiscpu);
    if (proc_list != NULL) {
        print_proc_list = NULL;
        monitor_printf(mon, "Eprocess              CR3                 PID   Full Process Path / [Process Name]\n");
        monitor_printf(mon, "--------------------- ------------------- ----- ----------------------------------\n");
        while ((print_proc_list = (process_list_st*)utarray_next(proc_list, print_proc_list))) {
            monitor_printf(mon, "0x%-20lx%-20lx%-5"PRId64" %s\n",
                    print_proc_list->eprocess,
                    print_proc_list->cr3,
                    print_proc_list->pid,
                    print_proc_list->full_file_path);
        }
        utarray_free(proc_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : List the running process handles
******************************************************************/
void do_list_process_handles(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    UT_array *handles;
    handles_st *print_handles;
    handles_node_st *print_handles_node;
    uint64_t handles_cr3 = 0x0;

    const char *target_type = NULL,
          *target = NULL;

    if (qdict_haskey(qdict, "target_type"))
        target_type = qdict_get_str(qdict, "target_type");
    if (qdict_haskey(qdict, "target"))
        target = qdict_get_str(qdict, "target");

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    // Choose parsing type
    if ((qdict_haskey(qdict, "target_type")^qdict_haskey(qdict, "target")) == 1) {
        monitor_printf(mon, "Wrong format\n");
        return;
    }
    else if (target_type == NULL && target == NULL) {
        handles = memfrs_enum_proc_handles(PARSING_HANDLE_TYPE_ALL, 0, thiscpu);
    }
    else {
        if (strcmp(target_type, "-c") == 0 || strcmp(target_type, "-C") == 0)
            handles = memfrs_enum_proc_handles(PARSING_HANDLE_TYPE_CR3, (uint64_t)strtoull(target, NULL, 16), thiscpu);
        else if (strcmp(target_type, "-e") == 0 || strcmp(target_type, "-E") == 0)
            handles = memfrs_enum_proc_handles(PARSING_HANDLE_TYPE_EPROCESS, (uint64_t)strtoull(target, NULL, 16), thiscpu);
        else if (strcmp(target_type, "-p") == 0 || strcmp(target_type, "-P") == 0)
            handles = memfrs_enum_proc_handles(PARSING_HANDLE_TYPE_PID, (uint64_t)strtoull(target, NULL, 10), thiscpu);
        else if (strcmp(target_type, "-t") == 0 || strcmp(target_type, "-T") == 0)
            handles = memfrs_enum_proc_handles_detail(PARSING_HANDLE_TYPE_TYPE, target, thiscpu);
        else if (strcmp(target_type, "-f") == 0 || strcmp(target_type, "-F") == 0)
            handles = memfrs_enum_proc_handles_detail(PARSING_HANDLE_TYPE_FULL_DETAIL, target, thiscpu);
        else if (strcmp(target_type, "-d") == 0 || strcmp(target_type, "-D") == 0)
            handles = memfrs_enum_proc_handles_detail(PARSING_HANDLE_TYPE_DETAIL, target, thiscpu);
        else {
            monitor_printf(mon, "Wrong format\n");
            return;
        }
    }


    if (handles != NULL) {
        print_handles = NULL;
        while ((print_handles=(handles_st*)utarray_next(handles,print_handles))) {
            if (handles_cr3 == 0x0 || print_handles->cr3 != handles_cr3) {
                handles_cr3 = print_handles->cr3;
                monitor_printf(mon, "\nCR3 : %"PRIx64"\t|\tERPOCESS: 0x%"PRIx64 "\t|\tPID: %"PRId64 "\t|\tImage name: %s\n",
                        print_handles->cr3,
                        print_handles->eprocess,
                        print_handles->pid,
                        print_handles->imagename);
                monitor_printf(mon, "Handle entry address  Index   Granted access           Type              Detail  \n");
                monitor_printf(mon, "-------------------- -------- -------------- ------------------------- ----------\n");
            }
            print_handles_node = NULL;
            while ((print_handles_node=(handles_node_st*)utarray_next(print_handles->handles_node, print_handles_node))) {
                monitor_printf(mon, "0x%-18"PRIx64 " 0x%-6"PRIx16 " 0x%-12"PRIx64 " %-25s %s\n",
                        print_handles_node->handle_table_entry_address,
                        print_handles_node->handle_table_entry_index,
                        print_handles_node->granted_access,
                        print_handles_node->type,
                        print_handles_node->detail);
            }
        }
        utarray_free(handles);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : List all types of handles
******************************************************************/
void do_list_handles_types(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    UT_array *handles_types;
    char **print_handles_types;

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    handles_types = memfrs_enum_handles_types(thiscpu);
    if (handles_types !=NULL) {

        monitor_printf(mon, " Handles Types \n");
        monitor_printf(mon, "---------------\n");

        print_handles_types = NULL;
        while ((print_handles_types=(char**)utarray_next(handles_types, print_handles_types))) {
            monitor_printf(mon, "%s\n", *print_handles_types);
        }
        utarray_free(handles_types); 
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : List the hive structure address and hive full path
******************************************************************/
void do_hive_list(Monitor *mon, const QDict *qdict)
{
    CPUState *cpu = NULL;
    UT_array *hive_list;
    hive_list_st *print_hive_list;

    int first_print;

    cpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    hive_list = memfrs_enum_hive_list(cpu);
    if (hive_list != NULL) {
        print_hive_list = NULL;
        monitor_printf(mon, "      Offset              Hive root path\n");
        monitor_printf(mon, "------------------  --------------------------------------------------\n");
        while ((print_hive_list=(hive_list_st*)utarray_next(hive_list, print_hive_list))) {
            monitor_printf(mon, "0x%"PRIx64"  ", print_hive_list->CMHIVE_address);

            first_print = 1;
            if (print_hive_list->file_full_path == NULL && print_hive_list->file_user_name == NULL && print_hive_list->hive_root_path == NULL) {
                monitor_printf(mon, "Unnamed\n");
            }
            else {
                if (print_hive_list->hive_root_path != NULL) {
                    monitor_printf(mon, "%s\n", print_hive_list->hive_root_path);
                    first_print = 0;
                }
                if (print_hive_list->file_user_name != NULL) {
                    if (first_print == 0)
                        monitor_printf(mon, "                    %s\n", print_hive_list->file_user_name);
                    else
                        monitor_printf(mon, "%s\n", print_hive_list->file_user_name);
                    first_print = 0;
                }
                if (print_hive_list->file_full_path != NULL) {
                    if (first_print == 0)
                        monitor_printf(mon, "                    %s\n", print_hive_list->file_full_path);
                    else
                        monitor_printf(mon, "%s\n", print_hive_list->file_full_path);
                }
            }
        }
        free(hive_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : List the ssdt
******************************************************************/
void do_list_ssdt(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    UT_array *ssdt_list;
    ssdt_list_st *print_ssdt_list;

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    ssdt_list = memfrs_enum_ssdt_list(thiscpu);
    if (ssdt_list != NULL) {
        print_ssdt_list = NULL;
        monitor_printf(mon, "Offset ArgNum on stack  System call addr         System call name         \n");
        monitor_printf(mon, "------ --------------- ------------------ --------------------------------\n");
        while ((print_ssdt_list=(ssdt_list_st*)utarray_next(ssdt_list,print_ssdt_list))) {
            monitor_printf(mon, "0x%-4x %15d 0x%-16"PRIx64" nt!%s\n",
                    print_ssdt_list->index,
                    print_ssdt_list->argnum_on_stack,
                    print_ssdt_list->address,
                    print_ssdt_list->system_call_name);
        }
        utarray_free(ssdt_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : List the hive structure address and hive full path
******************************************************************/
void do_regdump(Monitor *mon, const QDict *qdict)
{
    CPUState *cpu = NULL;
    UT_array *hive_list;
    hive_list_st *print_hive_list;
    uint64_t total_file_size;

    FILE *fd;
    const char *delim = "\\";
    char *target, *pch, *tmp_pch, *savestr;

    cpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    hive_list = memfrs_enum_hive_list(cpu);
    if (hive_list != NULL) {
        print_hive_list = NULL;
        while ((print_hive_list=(hive_list_st*)utarray_next(hive_list,print_hive_list))) {

            if (print_hive_list->file_full_path == NULL && print_hive_list->file_user_name == NULL && print_hive_list->hive_root_path == NULL) {
                target = (char*)malloc(29);
                sprintf(target, "Unnamed @ 0x%"PRIx64, print_hive_list->CMHIVE_address);
                savestr = strdup(target);
            }
            else {
                if (print_hive_list->file_full_path != NULL)
                    savestr = strdup(print_hive_list->file_full_path);
                else if (print_hive_list->file_user_name != NULL)
                    savestr = strdup(print_hive_list->file_user_name);
                else if (print_hive_list->hive_root_path != NULL)
                    savestr = strdup(print_hive_list->hive_root_path);
                else {
                    savestr = (char*)malloc(8);
                    sprintf(savestr, "Unnamed");
                }

                tmp_pch = NULL;
                pch = strdup(savestr);
                pch = strtok(pch, delim);
                while (pch != NULL) {
                    tmp_pch = pch;
                    pch = strtok(NULL, delim);
                }
                target = (char*)malloc(strlen(tmp_pch)+22);
                sprintf(target, "%s @ 0x%"PRIx64, tmp_pch, print_hive_list->CMHIVE_address);
            }

            fd = fopen(target, "w");
            if (fd == NULL)
                monitor_printf(mon, "Error opening file!\n");
            else {
                monitor_printf(mon, "*************************************************************************\n");
                total_file_size = memfrs_registry_dump(cpu, fd, print_hive_list->CMHIVE_address);
                monitor_printf(mon, "Dumping %s into \"%s\"\n", savestr, target);
                if (total_file_size <= BLOCK_SIZE)
                    monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
                monitor_printf(mon, "Dump %"PRIu64" bytes\n", total_file_size);
                fclose(fd);
            }

            free(target);
            free(savestr);
        }
        utarray_free(hive_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : Scan for the kernel module
******************************************************************/
void do_scan_module(Monitor *mon, const QDict *qdict)
{
    CPUState *cpu=NULL;
    UT_array *module_list;
    kernel_module_st *print_module_list;

    cpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    module_list = memfrs_scan_module(cpu);
    if (module_list != NULL) {
        print_module_list = NULL;
        monitor_printf(mon, "  Virtual address    Image size        Full module name      \n");
        monitor_printf(mon, "-------------------  ----------  ----------------------------\n");
        while ((print_module_list = (kernel_module_st*)utarray_next(module_list,print_module_list))) {
            monitor_printf(mon, "0x%-17"PRIx64"  %10"PRIu64"    %s\n",
                            print_module_list->virtual_addr,
                            print_module_list->image_size,
                            print_module_list->fullname);
        }
        utarray_free(module_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : Scan the running network
******************************************************************/
void do_scan_network(Monitor *mon, const QDict *qdict)
{
    CPUState *cpu=NULL;
    UT_array *network_list;
    network_state *print_network_list;

    cpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    network_list = memfrs_scan_network(cpu);
    if (network_list != NULL) {
        print_network_list = NULL;
        monitor_printf(mon, "Proto Phymemory       Eprocess        Image name     Pid      State                     Local address                      Foreign address          Time\n");
        monitor_printf(mon, "----- ---------- ------------------ --------------- ----- ------------- ---------------------------------------------- ---------------------- ------------------------\n");
        while ((print_network_list = (network_state*)utarray_next(network_list,print_network_list))) {
            monitor_printf(mon, "%s 0x%-8"PRIx64" 0x%"PRIx64" %-16s %-5"PRIu64" %-12s %-46s %-22s %s\n",
                    print_network_list->protocol, 
                    print_network_list->pmem, 
                    print_network_list->eprocess, 
                    print_network_list->imagename, 
                    print_network_list->pid, 
                    print_network_list->state, 
                    print_network_list->local_addr, 
                    print_network_list->foreign_addr, 
                    print_network_list->time);
        }
        utarray_free(network_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}



/******************************************************************
* PURPOSE : Fit the memory at addr into structure fields
******************************************************************/
void do_display_type(Monitor *mon, const QDict *qdict)
{
    CPUState *thiscpu = NULL;
    const char* struct_name = qdict_get_str(qdict, "struct");
    uint64_t addr = qdict_get_int(qdict, "addr");

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    memfrs_display_type(mon, thiscpu, addr, struct_name);
}



/******************************************************************
* PURPOSE : Trverse VAD tree
******************************************************************/
void do_traverse_vad(Monitor *mon, const QDict *qdict)
{
    UT_array *vad_list;
    vad_node* p;
    CPUState *thiscpu = NULL;
    uint64_t eprocess_ptr = qdict_get_int(qdict, "eprocess_addr");

    thiscpu = ENV_GET_CPU((CPUArchState*)mba_mon_get_cpu());

    vad_list = memfrs_traverse_vad_tree(eprocess_ptr, thiscpu);
    if (vad_list != NULL) {
        for (p = (vad_node*)utarray_front(vad_list) ; p!=NULL ; p = (vad_node*)utarray_next(vad_list, p))
            monitor_printf(mon, "%"PRIx64" -- %"PRIx64" %s\n", p->start_viraddr, p->end_viraddr, p->filename);
        utarray_free(vad_list);
    }
    else
        monitor_printf(mon, "%s\n", memfrs_get_last_error_message());
}
