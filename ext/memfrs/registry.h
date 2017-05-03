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


// process list
typedef struct hive_list_st{
    uint64_t CMHIVE_address;    // the hive root structure address
    char *file_full_path;      // file_full_path
    char *file_user_name;       // file_user_name
    char *hive_root_path;       // hive root path
}hive_list_st;



/*****************************************************************n
UT_array* memfrs_enum_hive_list( uint64_t kpcr_ptr, CPUState *cpu )

Eumerate the hive file

Requirement:    structure, global_structure
INPUT:          int64_t kpcr_ptr,       the address of _KPCR struct
                PUState *cpu,           the pointer to current cpu
OUTPUT:         T_array*                return a UT_array with ssdt data
*******************************************************************/
extern UT_array* memfrs_enum_hive_list( uint64_t kpcr_ptr, CPUState *cpu );
