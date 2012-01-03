/* 
 * Polyvaccine a Polymorphic exploit detection engine.
 *                                                              
 * Copyright (C) 2009  Luis Campo Giralte 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2009 
 *
 */

#ifndef _SUSPICIOUS_H_
#define _SUSPICIOUS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include "debug.h"
#include <sys/user.h>
#include <asm/unistd.h>

#define MAX_SYSCALL_NAME 32

enum {
        SYSCALL_LEVEL_INTERNAL = 0,
        SYSCALL_LEVEL_LOW,
        SYSCALL_LEVEL_MEDIUM,
        SYSCALL_LEVEL_HIGH
};

struct ST_SysCallSuspicious {
	int number;
	char name[MAX_SYSCALL_NAME];
	int level;
};

typedef struct ST_SysCallSuspicious ST_SysCallSuspicious;

struct ST_SysCall {
	char name[MAX_SYSCALL_NAME];
        int number;
	struct user_regs_struct regs; 
	int status;
};
typedef struct ST_SysCall ST_SysCall;

#define MAX_SYSCALL_SUSPICIOUS_TABLE 1 

static ST_SysCallSuspicious ST_SysCallSuspiciousTable [] = {
        { __NR_execve,          "execve",       SYSCALL_LEVEL_HIGH },
        { __NR_fork,            "fork",         SYSCALL_LEVEL_HIGH },
#ifdef _ASM_X86_UNISTD_32_H
        { __NR_socketcall,      "socketcall",   SYSCALL_LEVEL_HIGH},
#endif
        { __NR_write,           "write",        SYSCALL_LEVEL_MEDIUM },
        { __NR_exit,            "exit",         SYSCALL_LEVEL_HIGH },
        { __NR_open,            "open",         SYSCALL_LEVEL_HIGH},
        { 0,			"none",		SYSCALL_LEVEL_INTERNAL}
};


ST_SysCall *SUSY_New(char *name,struct user_regs_struct *u,int status);
void SUSY_Printf(ST_SysCall *c);
void SUSY_Destroy(ST_SysCall *c);
#endif
