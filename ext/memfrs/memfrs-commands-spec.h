/*
 *  MBA Virtual Machine Memory Forensic qemu command specification
 *
 *  Copyright (c)   2016 Chongkuan Chen
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
{
        .name = "mba_scan_kernel",
        .args_type  = "",
        .params     = "",
        .help       = "Scan for the kernel",
        .mhandler.cmd = do_scan_kernel,
},
{
        .name = "mba_gen_pdb_profiles",
        .args_type  = "profiles_dir:F",
        .params     = "profiles_dir",
        .help       = "Generate PDB's global var and structure info into profiles_dir",
        .mhandler.cmd = do_gen_pdb_profiles,
},
{
        .name = "mba_load_structures",
        .args_type  = "sdb:F",
        .params     = "sdb",
        .help       = "Load structures information",
        .mhandler.cmd = do_load_structures,
},
{
        .name = "mba_load_global_variable",
        .args_type  = "gvar_db:F",
        .params     = "gvar_db",
        .help       = "Load global variable information",
        .mhandler.cmd = do_load_global_variable,
},
{
        .name = "mba_scan_virmem_pattern",
        .args_type  = "start:l,end:l,pattern:s",
        .params     = "start end pattern",
        .help       = "Scan the virmem for the specific pattern",
        .mhandler.cmd = do_scan_virmem,
},
{
        .name = "mba_scan_phymem_pattern",
        .args_type  = "start:l,end:l,pattern:s",
        .params     = "start end pattern",
        .help       = "Scan the phymem for the specific pattern",
        .mhandler.cmd = do_scan_phymem,
},
{
        .name = "mba_show_virmem_content",
        .args_type  = "addr:l,len:l,cr3:l?",
        .params     = "addr len [cr3]",
        .help       = "Show the virtual mem content starting at <addr> with length <len>",
        .mhandler.cmd = do_show_virmem_content,
},
{
        .name = "mba_show_phymem_content",
        .args_type  = "addr:l,len:l",
        .params     = "addr len",
        .help       = "Show the physical mem content starting at <addr> with length <len>",
        .mhandler.cmd = do_show_phymem_content,
},
{
        .name = "mba_get_gvar_vmem",
        .args_type  = "gvar:s",
        .params     = "gvar",
        .help       = "Get the virtual memory address of the global variable/symbol\n"
                      "Required : global data structure",
        .mhandler.cmd = do_get_gvar_vmem,
},
{
        .name = "mba_get_gvar_name",
        .args_type  = "addr:l",
        .params     = "addr",
        .help       = "Get the symbol name at specific virtual memory address\n"
                      "The address is an offset to kernel base address\n"
                      "Required : global data structure",
        .mhandler.cmd = do_get_gvar_name,
},
{
        .name = "mba_get_physic_address",
        .args_type  = "cr3:l,addr:l",
        .params     = "cr3 addr",
        .help       = "Get the physic address of a given virtual address in memory space(cr3)",
        .mhandler.cmd = do_get_physic_address,
},
{
        .name = "mba_get_windows_version",
        .args_type  = "",
        .params     = "",
        .help       = "Get the Windows version\n"
                      "Required : data structure, global data structure",
        .mhandler.cmd = do_get_windows_version,
},
{
        .name = "mba_list_processes",
        .args_type  = "",
        .params     = "",
        .help       = "List running processes\n"
                      "Required : data structure",
        .mhandler.cmd = do_list_process,
},
{
        .name = "mba_list_handles",
        .args_type  = "target_type:s?,target:s?",
        .params     = "[-c cr3 | -e eprocess | -t handles_type]",
        .help       = "List process running handles.\n"
                       "-c cr3 : parse handles of process by process' cr3\n"
                       "-e eprocess : parse handles of process by process' eprocess\n"
                       "-p pid : parse handles of process by process' pid\n"
                       "-t handles_type : parse only handles of handles_type"
                       "-f full_detail : parse only exactly match full_detail with handles' detail\n"
                       "-d detail : parse section matched detail with handles' detail\n"
                       "Required : data structure, global data structure",
        .mhandler.cmd = do_list_process_handles,
},
{
        .name = "mba_list_handles_types",
        .args_type  = "",
        .params     = "",
        .help       = "List all types of handles\n"
                      "Required : data structure, global data structure",
        .mhandler.cmd = do_list_handles_types,
},
{
        .name = "mba_list_hives",
        .args_type  = "",
        .params     = "",
        .help       = "List all hive structure address and full path of hive\n"
                      "Required : data structure, global data structure",
        .mhandler.cmd = do_hive_list,
},
{
        .name = "mba_list_ssdt",
        .args_type  = "",
        .params     = "",
        .help       = "List all system call name, address and argument numbers\n"
                      "Required : global data structure",
        .mhandler.cmd = do_list_ssdt,
},
{
        .name = "mba_regdump",
        .args_type  = "",
        .params     = "",
        .help       = "Dump all hive files\n"
                      "Required : data structure, global data structure",
        .mhandler.cmd = do_regdump,
},
{
        .name = "mba_scan_module",
        .args_type  = "",
        .params     = "",
        .help       = "Scan physical address for the kernel module\n"
                      "Required : data structure",
        .mhandler.cmd = do_scan_module,
},
{
        .name = "mba_scan_network",
        .args_type  = "",
        .params     = "",
        .help       = "Scan physical address for the network\n"
                      "Required : data structure, netowrk data structure",
        .mhandler.cmd = do_scan_network,
},
{
        .name = "mba_dt",
        .args_type  = "addr:l,struct:s",
        .params     = "addr struct",
        .help       = "Fit the memory at addr into structure fields",
        .mhandler.cmd = do_display_type,
},
{
        .name = "mba_travers_vad",
        .args_type  = "eprocess_addr:l",
        .params     = "eprocess_addr",
        .help       = "Trverse VAD tree\n"
                      "Required : data structure",
        .mhandler.cmd = do_traverse_vad,
},
