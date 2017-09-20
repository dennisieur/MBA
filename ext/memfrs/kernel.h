/*
 *  MBA Virtual Machine Memory Introspection header
 *
 *  Copyright (c)   2016 ChongKuan Chen
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



#ifndef __MEMFRS_KERNEL_H__
#define __MEMFRS_KERNEL_H__

#if !defined(CONFIG_MEMFRS_TEST)
#include "qom/cpu.h"
#endif



typedef struct win_kernel_module{
    char name[256];
    uint64_t base;
    char guid[80];
}win_kernel_module;



//Leave for private APIs



#endif
