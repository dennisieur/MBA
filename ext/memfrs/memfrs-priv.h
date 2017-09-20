/*
 *  MBA Virtual Machine Memory Forensic extension of qemu command header
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

#ifndef __MEMFRS_PRIV_H__
#define __MEMFRS_PRIV_H__


extern uint64_t g_kpcr_ptr;
extern json_object *g_struct_info;
extern json_object *g_globalvar_info;



/*******************************************************************
/// Get the memory content in virtual memory
/// monitor print message on screem
///
/// \param mon          Monitor
/// \param buf          target buffer
/// \param length       length of buffer
///
/// no return value
*******************************************************************/
extern void hexdump(Monitor *mon, uint8_t* buf, size_t length);



/*******************************************************************
/// Get the memory content in virtual memory
///
/// \param ustr_ptr     unicode structure address
/// \param cr3          cr3 value, 0 if no specific process
/// \param cpu          current cpu
///
/// return an ascii string, return NULL if failed
*******************************************************************/
extern char* parse_unicode_strptr(uint64_t ustr_ptr, uint64_t cr3, CPUState *cpu);



/*******************************************************************
/// Get the memory content in virtual memory
///
/// \param ustr         unicode string
/// \param cpu          current cpu
///
/// return an ascii string, return NULL if failed
*******************************************************************/
extern char* parse_unicode_str(uint8_t* ustr, CPUState *cpu);



#endif
