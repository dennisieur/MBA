/*
 *  MBA Virtual Machine Memory Introspection implementation
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



#include <unistd.h>

#if !defined(CONFIG_MEMFRS_TEST)
#include "qemu-common.h"
#endif

#include "memfrs.h"
#include "kernel.h"

#define PE_HEADER "MZ"
#define RSDS_HEADER_SIG "RSDS"
#define RSDS_HEADER_SIZE 0x30
#define RSDS_HEADER_IMAGE_NAME_OFF 0x18

#define INIT_LOADER_MAP_LOW 0xFFFFF80000000000 

#if !defined(CONFIG_MEMFRS_TEST)
#define INIT_LOADER_MAP_HIGH 0xFFFFF87FFFFFFFFF
#define SEARCH_MAX 0x1000000
#else
#define INIT_LOADER_MAP_HIGH INIT_LOADER_MAP_LOW+0x2000
#define SEARCH_MAX 0x100
#endif

#define PDB_TMP_PATH "/tmp/"
#define CURL_AGENT "Microsoft-Symbol-Server/6.11.0001.402"
#define TMP_PDB_PARSER_PATH "ext/memfrs/pdbparser/pdb_parser"

#define GUID_SIZE 80
#define COMMAND_SIZE 256
#define BASENAME_SIZE 256

uint64_t nt_kernel_base = 0;
win_kernel_module* g_win_kernel = NULL;



/******************************************************************
* PURPOSE : Parse GUID, return -1 for parse failed
******************************************************************/
static int parse_GUID(CPUState* cpu, uint64_t addr, char* guid)
{
    int i;
    uint32_t data1;
    uint16_t data2,
             data3;
    uint8_t  data4[8];
    uint32_t age;         

    if (cpu_memory_rw_debug(cpu, addr, (uint8_t*)&data1, sizeof(data1), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }
    if (cpu_memory_rw_debug(cpu, addr+4, (uint8_t*)&data2, sizeof(data2), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }
    if (cpu_memory_rw_debug(cpu, addr+6, (uint8_t*)&data3, sizeof(data3), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }
    if (cpu_memory_rw_debug(cpu, addr+8, (uint8_t*)&data4, 8 * sizeof(uint8_t), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }
    if (cpu_memory_rw_debug(cpu, addr+16, (uint8_t*)&age, sizeof(uint32_t), 0) != 0) {
        memfrs_errno = MEMFRS_ERR_MEMORY_READ_FAILED;
        return -1;
    }

    snprintf(guid, GUID_SIZE, "%08X%04X%04X", data1, data2, data3);
    for (i=0 ; i<8 ; ++i)
        snprintf(guid+16+2*i, GUID_SIZE, "%02X", data4[i]);
    snprintf(guid+32, GUID_SIZE, "%X", age);
    return 0;
}



/******************************************************************
* PURPOSE : Download PDB, return -1 for download failed
******************************************************************/
static int download_pdb(win_kernel_module* win_kernel, const char* profile_path)
{
    char cmd[COMMAND_SIZE];
    char basename[BASENAME_SIZE];
    int ret;
  
    strcpy(basename, win_kernel->name);
    basename[strlen(basename)-1]='_';

    memset(cmd, 0, COMMAND_SIZE);
    snprintf(cmd, COMMAND_SIZE-1, "curl -sA \"%s\" \"http://msdl.microsoft.com/download/symbols/%s/%s/%s\" -o /tmp/%s",
             CURL_AGENT , win_kernel->name, win_kernel->guid, basename, basename);
    ret = system(cmd);
    if (ret != 0) {
        memfrs_errno = MEMFRS_ERR_COMMAND_EXECUTE_FAILED;
        return -1;
    }

    // Unpresee symbol file
    memset(cmd, 0, COMMAND_SIZE);
    snprintf(cmd, COMMAND_SIZE-1, "cabextract -d \"" PDB_TMP_PATH "\" \"" PDB_TMP_PATH "%s\"", basename);
    ret = system(cmd);
    if (ret != 0) {
        memfrs_errno = MEMFRS_ERR_COMMAND_EXECUTE_FAILED;
        return -1;
    }

    // Parse symbol file
    if (access(TMP_PDB_PARSER_PATH, F_OK ) == -1) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_PDB_PARSER;
        return -1;
    }

    memset(cmd, 0, COMMAND_SIZE);
    snprintf(cmd, COMMAND_SIZE-1, TMP_PDB_PARSER_PATH " %s%s %s", PDB_TMP_PATH, win_kernel->name, profile_path);

    ret = system(cmd);
    if (ret != 0) {
        memfrs_errno = MEMFRS_ERR_COMMAND_EXECUTE_FAILED;
        return -1;
    }

    return ret;
}



extern uint64_t memfrs_find_nt_kernel_base(CPUState* cpu)
{
    nt_kernel_base = 0;

    uint64_t i, j, x;
    uint64_t rsds_off = 0;
    bool find = 0;
    uint8_t* buf = (uint8_t*)malloc(RSDS_HEADER_SIZE+1);
    const char* kernel_list[] = {"ntoskrnl.pdb",
                                 "ntkrnlpa.pdb",
                                 "ntkrnlmp.pdb",
                                 0};

    if (g_win_kernel != NULL) {
        free(g_win_kernel);
        g_win_kernel = NULL;
    }

    for (i=INIT_LOADER_MAP_LOW ; i<INIT_LOADER_MAP_HIGH ; i+=0x1000) {
        cpu_memory_rw_debug(cpu, i, buf, strlen(PE_HEADER), 0);
        if (memcmp(buf, PE_HEADER, strlen(PE_HEADER)) == 0) {
            for (j=i ; j<i+SEARCH_MAX ; ++j) {
                cpu_memory_rw_debug(cpu, j, buf, RSDS_HEADER_SIZE, 0);
                // TODO: Not use magic number, use ds query system instead
                if (memcmp(buf, RSDS_HEADER_SIG, strlen(RSDS_HEADER_SIG)) == 0) {
                    rsds_off = j;
                    break;
                }
            }

            for (x=0 ; kernel_list[x] ; ++x) {
                // Find windows kernel
                if (memcmp(buf+RSDS_HEADER_IMAGE_NAME_OFF, kernel_list[x], strlen(kernel_list[x])) == 0) {
                    g_win_kernel = (win_kernel_module*)calloc(1, sizeof(win_kernel_module));
                    find = 1;
                    strncpy(g_win_kernel->name, kernel_list[x], 255);
                    g_win_kernel->base = i;
                    nt_kernel_base = i;
                    if (parse_GUID(cpu, rsds_off+strlen(RSDS_HEADER_SIG), g_win_kernel->guid) == -1) {
                        free(buf);
                        return 0;
                    }
                    break;
                }
            }
            
            if (find)
                break;
        }
    }

    free(buf);
    if (find == 0)
        return 0;

    return nt_kernel_base;
}



extern uint64_t memfrs_get_nt_kernel_base(void)
{
    return nt_kernel_base;
}



extern void* memfrs_get_kernel_info(void)
{
    return (void*)g_win_kernel;
}



extern int memfrs_gen_pdb_profiles(const char* profile_dir)
{
    if (g_win_kernel == NULL) {
        memfrs_errno = MEMFRS_ERR_NOT_FOUND_WINDOWS_KERNEL;
        return -1;
    }
    if (profile_dir == NULL) {
        memfrs_errno = MEMFRS_ERR_INVALID_MBA_MEMFRS_COMMAND;
        return -1;
    }
    return download_pdb(g_win_kernel, profile_dir);
}
