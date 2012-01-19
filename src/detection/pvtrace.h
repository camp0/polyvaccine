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

#ifndef _PVTRACE_H_
#define _PVTRACE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "debug.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#ifdef __LINUX__
#ifdef __WORDSIZE == 64
#define REG_AX(a) a.orig_rax
#define REG_BX(a) a.rbx
#define REG_CX(a) a.rcx
#define REG_DX(a) a.rdx
#define REG_CS(a) a.cs
#define REG_IP(a) a.rip
#define REG_DI(a) a.rdi
#define REG_SI(a) a.rsi

#else
#define REG_AX(a) a.orig_eax 
#define REG_BX(a) a.ebx
#define REG_CX(a) a.ecx
#define REG_DX(a) a.edx
#endif
#endif // __LINUX__
#ifdef __FREEBSD__
#define REG_AX(a) a.r_rax
#define REG_BX(a) a.r_rbx
#define REG_CX(a) a.r_rcx
#define REG_DX(a) a.r_rdx
#define REG_CS(a) a.r_cs
#define REG_IP(a) a.r_rip
#define REG_DI(a) a.r_rdi
#define REG_SI(a) a.r_rsi
#endif




int PTRC_TraceMe(void);
int PTRC_TraceContinue(pid_t pid,int sig, char *addr);
int PTRC_TraceKill(pid_t pid);
int PTRC_TraceSyscall(pid_t pid,int sig);
int PTRC_TraceGetRegisters(pid_t pid, void *regs);
int PTRC_TraceSetRegisters(pid_t pid, void *regs);

#endif
