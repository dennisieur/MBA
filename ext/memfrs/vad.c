/*
 *  MBA VAD Introspection Implementation
 *
 *  Copyright (c)   2016 ChongKuan Chen
 *                  2017 ELin Ho
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
#include "vad.h"



// UT_array's eelement structure for vad address
UT_icd vad_adr_icd = {sizeof(uint64_t), NULL, NULL, NULL};
UT_icd vad_node_icd = {sizeof(vad_node), NULL, NULL, NULL};



// Mapping between VAD type and it's name
const char *MI_VAD_TYPE_STR[] = {
    "VadNone",
    "VadDevicePhysicalMemory",
    "VadImageMap",
    "VadAwe",
    "VadWriteWatch",
    "VadLargePages",
    "VadRotatePhysical",
    "VadLargePageSection"
};



// Mapping between page permission and it's description
const char *PAGE_PERMISSION_STR[] = {
    "PAGE_NOACCESS",
    "PAGE_READONLY",
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_READWRITE",
    "PAGE_WRITECOPY",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
    "PAGE_NOACCESS",
    "PAGE_NOCACHE | PAGE_READONLY",
    "PAGE_NOCACHE | PAGE_EXECUTE",
    "PAGE_NOCACHE | PAGE_EXECUTE_READ",
    "PAGE_NOCACHE | PAGE_READWRITE",
    "PAGE_NOCACHE | PAGE_WRITECOPY",
    "PAGE_NOCACHE | PAGE_EXECUTE_READWRITE",
    "PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY",
    "PAGE_NOACCESS",
    "PAGE_GUARD | PAGE_READONLY",
    "PAGE_GUARD | PAGE_EXECUTE",
    "PAGE_GUARD | PAGE_EXECUTE_READ",
    "PAGE_GUARD | PAGE_READWRITE",
    "PAGE_GUARD | PAGE_WRITECOPY",
    "PAGE_GUARD | PAGE_EXECUTE_READWRITE",
    "PAGE_GUARD | PAGE_EXECUTE_WRITECOPY",
    "PAGE_NOACCESS",
    "PAGE_WRITECOMBINE | PAGE_READONLY",
    "PAGE_WRITECOMBINE | PAGE_EXECUTE",
    "PAGE_WRITECOMBINE | PAGE_EXECUTE_READ",
    "PAGE_WRITECOMBINE | PAGE_READWRITE",
    "PAGE_WRITECOMBINE | PAGE_WRITECOPY",
    "PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE",
    "PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY",
};



/*********************************************************************************
/// Parsing the vad node information by the given VAD node(MMVAD) virtual address.
/// Output is throw to stdout.
///
/// \param mmvad_ptr    the virtual address to the VAD node
/// \param cpu          pointer to current cpu
///
/// return vad node pointer, and NULL if error
**********************************************************************************/
static vad_node* parse_mmvad_node(uint64_t mmvad_ptr, CPUState *cpu)
{
    uint64_t file_pointer_ptr;
    uint64_t start_viraddr,
             end_viraddr;
    uint32_t starting_vpn,
             ending_vpn,
             u;
    uint8_t  starting_vpn_high,
             ending_vpn_high;

    int offset_filename_to_fileobj = 0;
    int vad_type,
        vad_protection;
    char *filename;

    vad_node* vad = (vad_node*)malloc(sizeof(vad_node));

    // Qery VAD Virtual Address range
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&starting_vpn, sizeof(starting_vpn), mmvad_ptr, false, "_MMVAD_SHORT", 1, "#StartingVpn");
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&ending_vpn, sizeof(ending_vpn), mmvad_ptr, false, "_MMVAD_SHORT", 1, "#EndingVpn");
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&starting_vpn_high, sizeof(starting_vpn_high), mmvad_ptr, false, "_MMVAD_SHORT", 1, "#StartingVpnHigh");
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&ending_vpn_high, sizeof(ending_vpn_high), mmvad_ptr, false, "_MMVAD_SHORT", 1, "#EndingVpnHigh");

    start_viraddr = (( (uint64_t)starting_vpn_high << 32 ) + starting_vpn ) << 12;
    end_viraddr = ((( (uint64_t)ending_vpn_high << 32 ) + ending_vpn ) << 12 ) + 0xfff;
    //printf("VAD vir range %" PRIx64 " <---------> %" PRIx64 "\n", start_viraddr, end_viraddr); // only for checking

    // Query for VAD node metadata
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&u, sizeof(u), mmvad_ptr, false, "_MMVAD_SHORT", 1, "#u");
    vad_type = u & 0b111;
    vad_protection = ((u >> 3) & 0b11111);
    //printf("VAD type: %s(%x)\n", MI_VAD_TYPE_STR[vad_type], vad_type); // only for checking
    //printf("Permission: %s(%x)\n", PAGE_PERMISSION_STR[vad_protection], vad_protection); // only for checking

    vad->start_viraddr = start_viraddr; 
    vad->end_viraddr = end_viraddr;
    vad->vad_type = vad_type;
    vad->vad_protection = vad_protection;
    vad->filename = NULL;   

    // Check if mode is immage mapping
    if (vad_type != VadImageMap)
        return vad;

    // Quey image filename by following path 
    // _MMVAD->Subsection->ControlArea->FilePointer/_FILE_OBJECT->FileName
    memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&file_pointer_ptr, sizeof(file_pointer_ptr), mmvad_ptr, false, "_MMVAD", 3, "*Subsection", "*ControlArea", "*FilePointer");

    // _FILE_OBJECT is always aligned, mask out filepointer's lowest byte, which s used to save metadata 
    file_pointer_ptr &= 0xfffffffffffffff0;
    if (file_pointer_ptr == 0)
        return vad;

    // Parse the unicode string
    memfrs_get_nested_field_offset(&offset_filename_to_fileobj, "_FILE_OBJECT", 1, "FileName");
    filename = parse_unicode_strptr(file_pointer_ptr + offset_filename_to_fileobj, 0, cpu);
    vad->filename = filename;

    return vad;
}



extern UT_array* memfrs_traverse_vad_tree(uint64_t eprocess_ptr, CPUState *cpu)
{
    UT_array *vad_adr_queue;
    UT_array *vad_node_queue;
    uint64_t *current_node;
    uint64_t vad_root = 0,
             left,
             right;

    // Check if ds metadata is already loaded
    if (memfrs_check_struct_info() == 0) {
        memfrs_errno = MEMFRS_ERR_NOT_LOADED_STRUCTURE;
        return NULL;
    }


    // Initialize vad_node_queue, use UT_arry as the queue 
    utarray_new(vad_adr_queue, &vad_adr_icd);
    utarray_new(vad_node_queue, &vad_node_icd);

    // Read vad root node from memory
    if (memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&vad_root, sizeof(vad_root), eprocess_ptr, false, "_EPROCESS", 1, "#VadRoot") == -1)
        return NULL;
    if (vad_root == 0)
        return NULL;
    //printf("vad root: %" PRIx64 "\n", vad_root); // only for checking

    // Put vad root into queue as first element
    utarray_push_back(vad_adr_queue, &vad_root);

    // Walk through the QUEUE
    while(utarray_len(vad_adr_queue) != 0) {
        current_node = (uint64_t*)utarray_back(vad_adr_queue);
        //printf("Find Node %" PRIx64 "\n", *current_node); // only for checking

        // Parse the vad node   
        vad_node* vad = parse_mmvad_node(*current_node, cpu);
        utarray_push_back(vad_node_queue, vad);

        // Read Left node
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&left, sizeof(left), (*current_node), false, "_RTL_BALANCED_NODE", 1, "#Left");

        // Read Right node
        memfrs_get_mem_struct_content(cpu, 0, (uint8_t*)&right, sizeof(right), (*current_node), false, "_RTL_BALANCED_NODE", 1, "#Right");

        // Find the next node
        utarray_pop_back(vad_adr_queue);
   
        // Push node into queue if the node found
        if (left != 0)
            utarray_push_back(vad_adr_queue, &left);
        if (right != 0)
            utarray_push_back(vad_adr_queue, &right);
        //printf("Node left %" PRIx64 "\n", left);  // only for checking
        //printf("Node left %" PRIx64 "\n", right); // only for checking
    }

    return vad_node_queue;
}
