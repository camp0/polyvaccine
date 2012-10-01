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

#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "debug.h"
#include <signal.h>
#ifdef __LINUX__
#include <asm/unistd.h>
#endif
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include "context.h"
#include "pvtrace.h"
#include "../core/trustoffset.h"
#include "interfaces.h"
#include "segment.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define MAX_SYSCALL_NAME 32

enum {
	PROCESS_EXIT = 0,
	PROCESS_RUNNING 
};

enum {
	ERROR_PTRACE = 10,
	ERROR_KILL
};

enum {
	EXPECT_EXITED = 1,
	EXPECT_SIGNALED,
	EXPECT_UNKNOWN,
	EXPECT_STOPPED
};

struct ST_ProcessExitCode {
        int signal;
        char *description;
        int received;
};
typedef struct ST_ProcessExitCode ST_ProcessExitCode;

struct ST_ProcessSysCallFlow {
	//GSList *flow;
};
typedef struct ST_ProcessSysCallFlow ST_ProcessSysCallFlow;	

struct ST_Tracer {
	GHashTable *syscalls; // a pointer to ST_SysCallSuspicious
	GHashTable *syscalltable; 
	GSList *flow; // a single list of the syscalls maded by a process, stores ST_SysCall types
	pid_t child_pid;
	int show_execution_path;
	int block_syscalls_eax;

	/* Info shared with the child */
	ST_SharedContext *ctx;
	char buffer[1024];
	ST_ExecutableSegment *sx;	
};
typedef struct ST_Tracer ST_Tracer;

#define SIZE(a) (sizeof(a)/sizeof((a)[0]))

enum LINUX_CALL_TYPES {
	LINUX64 = 0,
	LINUX32 = 1,
	LINUX_NUM_VERSIONS = 2
};

static enum LINUX_CALL_TYPES
linux_call_type(long codesegment) 
{
	if (codesegment == 0x33)
		return (LINUX64);
	else if (codesegment == 0x23)
		return (LINUX32);
        else {
		fprintf(stdout,"%s:%d: unknown code segment %lx\n",
		    __FILE__, __LINE__, codesegment);
		return -1;
	}
}

#ifdef PTRACE_LINUX64
#define ISLINUX32(x)		(linux_call_type((x)->cs) == LINUX32)
#define SYSCALL_NUM(x)		(x)->orig_rax
#define SET_RETURN_CODE(x, v)	(x)->rax = (v)
#define RETURN_CODE(x)		(ISLINUX32(x) ? (long)(int)(x)->rax : (x)->rax)
#define ARGUMENT_0(x)		(ISLINUX32(x) ? (x)->rbx : (x)->rdi)
#define ARGUMENT_1(x)		(ISLINUX32(x) ? (x)->rcx : (x)->rsi)
#define ARGUMENT_2(x)		(ISLINUX32(x) ? (x)->rdx : (x)->rdx)
#define ARGUMENT_3(x)		(ISLINUX32(x) ? (x)->rsi : (x)->rcx)
#define ARGUMENT_4(x)		(ISLINUX32(x) ? (x)->rdi : (x)->r8)
#define ARGUMENT_5(x)		(ISLINUX32(x) ? (x)->rbp : (x)->r9)
#define SET_ARGUMENT_0(x, v)	if (ISLINUX32(x)) (x)->rbx = (v); else (x)->rdi = (v)
#define SET_ARGUMENT_1(x, v)	if (ISLINUX32(x)) (x)->rcx = (v); else (x)->rsi = (v)
#define SET_ARGUMENT_2(x, v)	if (ISLINUX32(x)) (x)->rdx = (v); else (x)->rdx = (v)
#define SET_ARGUMENT_3(x, v)	if (ISLINUX32(x)) (x)->rsi = (v); else (x)->rcx = (v)
#define SET_ARGUMENT_4(x, v)	if (ISLINUX32(x)) (x)->rdi = (v); else (x)->r8 = (v)
#define SET_ARGUMENT_5(x, v)	if (ISLINUX32(x)) (x)->rbp = (v); else (x)->r9 = (v)
#else
#define SYSCALL_NUM(x)		(x)->orig_eax
#define SET_RETURN_CODE(x, v)	(x)->eax = (v)
#define RETURN_CODE(x)		(x)->eax
#define ARGUMENT_0(x)		(x)->ebx
#define ARGUMENT_1(x)		(x)->ecx
#define ARGUMENT_2(x)		(x)->edx
#define ARGUMENT_3(x)		(x)->esi
#define ARGUMENT_4(x)		(x)->edi
#define ARGUMENT_5(x)		(x)->ebp
#define SET_ARGUMENT_0(x, v)	(x)->ebx = (v)
#define SET_ARGUMENT_1(x, v)	(x)->ecx = (v)
#define SET_ARGUMENT_2(x, v)	(x)->edx = (v)
#define SET_ARGUMENT_3(x, v)	(x)->esi = (v)
#define SET_ARGUMENT_4(x, v)	(x)->edi = (v)
#define SET_ARGUMENT_5(x, v)	(x)->ebp = (v)
#endif /* !PTRACE_LINUX64 */


void SYSU_Init(void);
void SYSU_Destroy(void);
void SYSU_ShowExecutionPath(int value);
void SYSU_BlockDetectedSyscalls(int value);
int SYSU_AnalyzeSegmentMemory(char *buffer, int size, ST_TrustOffsets *t_off);

#endif
