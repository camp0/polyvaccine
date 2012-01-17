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

#include "pvtrace.h"

int PTRC_TraceMe(void){
	int ret = 0;

#ifdef __LINUX__
	ret = !(0 > ptrace(PTRACE_TRACEME,0,NULL,NULL));
#endif
#ifdef __FREEBSD__
	ret = !(0 > ptrace(PT_TRACE_ME,0,NULL,0));
#endif	
	return ret;
}

int PTRC_TraceContinue(pid_t pid,int sig, char *addr){
	int ret = 0;
#ifdef __LINUX__
	ret = !(0 > ptrace(PTRACE_CONT,pid,NULL,sig));
#endif
#ifdef __FREEBSD__
	ret = !(0 > ptrace(PT_STEP,pid,(caddr_t)1,sig));
#endif
	return ret;
}

int PTRC_TraceKill(pid_t pid){
	int ret = 0;
#ifdef __LINUX__
	ret = !(0 > ptrace(PTRACE_KILL,pid,NULL,NULL));
#endif
#ifdef __FREEBSD__
	ret = !(0 > ptrace(PT_KILL,pid,NULL,0));
#endif
	return ret;
}

int PTRC_TraceSyscall(pid_t pid,int sig){
        int ret = 0;
#ifdef __LINUX__
	ret = !(0 > ptrace(PTRACE_SYSCALL,pid,NULL,sig));
#endif
#ifdef __FREEBSD__
	ret = !(0 > ptrace(PT_SYSCALL,pid,(caddr_t)1,sig));
#endif
        return ret;
}


int PTRC_TraceGetRegisters(pid_t pid, void *regs){
	int ret = 0;
#ifdef __LINUX__
	ret = !(0 > ptrace(PTRACE_GETREGS,pid,0,regs));
#endif
#ifdef __FREEBSD__
	ret = !(0 > ptrace(PT_GETREGS,pid,(caddr_t)regs,0));
#endif
	return ret;
}

int PTRC_TraceSetRegisters(pid_t pid, void *regs){
        int ret = 0;
#ifdef __LINUX__
        ret = !(0 > ptrace(PTRACE_SETREGS,pid,0,regs));
#endif
#ifdef __FREEBSD__
        ret = !(0 > ptrace(PT_SETREGS,pid,(caddr_t)regs,0));
#endif
        return ret;
}
