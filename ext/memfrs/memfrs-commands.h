/*
 *  MBA Virtual Machine Memory Forensic extension of qemu command header
 *
 *  Copyright (c)   2012 Chiwei Wang
 *                  2016 Chiawei Wang
 *                  2016 Chongkuan Chen
 *                  2016 Hao Li
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

#ifndef __MEMFRS_COMMAND_H_
#define __MEMFRS_COMMAND_H_

struct Monitor;
struct QDict;


// Scan kernel base
void do_scan_kernel(Monitor *mon, const QDict *qdict);
// Generate PDB's global var and structure info into profiles_dir
void do_gen_pdb_profiles(Monitor *mon, const QDict *qdict);
// Load data structure
void do_load_structures(Monitor *mon, const QDict *qdict);
void do_load_global_variable(Monitor *mon, const QDict *qdict);

// Scan the memory for the specific pattern
void do_scan_virmem(Monitor *mon, const QDict *qdict);
void do_scan_phymem(Monitor *mon, const QDict *qdict);

// Show the physical mem content starting at <addr> with length <len>
void do_show_virmem_content(Monitor *mon, const QDict *qdict);
void do_show_phymem_content(Monitor *mon, const QDict *qdict);

// Get the virtual memory address of symbols with name gvar
void do_get_gvar_vmem(Monitor *mon, const QDict *qdict);
// Get the symbol name at specific virtual memory address
void do_get_gvar_name(Monitor *mon, const QDict *qdict);
// Get the physic address of a given virtual address in memory space(cr3)
void do_get_physic_address(Monitor *mon, const struct QDict *qdict);
// Get windows version
void do_get_windows_version(Monitor *mon, const QDict *qdict);

// List the running process
void do_list_process(Monitor *mon, const QDict *qdict);
// List the running process handles
void do_list_process_handles(Monitor *mon, const QDict *qdict);
// List all types of handles
void do_list_handles_types(Monitor *mon, const QDict *qdict);
// List all hives
void do_hive_list(Monitor *mon, const QDict *qdict);
// List the ssdt
void do_list_ssdt(Monitor *mon, const QDict *qdict);

// Dump registries
void do_regdump(Monitor *mon, const QDict *qdict);

// Scan for the kernel module
void do_scan_module(Monitor *mon, const QDict *qdict);
// Scan the running network
void do_scan_network(Monitor *mon, const QDict *qdict);

// Fit the memory at addr into structure fields
void do_display_type(Monitor *mon, const QDict *qdict);
// Trverse VAD tree
void do_traverse_vad(Monitor *mon, const QDict *qdict);


#endif
