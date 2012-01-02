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
#include "suspicious.h"

ST_SysCall *SUSY_New(char *name,struct user_regs_struct *u,int status) {
//	ST_SysCall *sys = (ST_SysCall*)malloc(sizeof(ST_SysCall));
	ST_SysCall *sys = g_new0(ST_SysCall,1);

	snprintf(sys->name,32,"%s",name);
#if __WORDSIZE == 64
	sys->regs.r15 = u->r15;
  	sys->regs.r14 = u->r14;
  	sys->regs.r13 = u->r13;
  	sys->regs.r12 = u->r12;
  	sys->regs.rbp = u->rbp;
  	sys->regs.rbx = u->rbx;
  	sys->regs.r11 = u->r11;
  	sys->regs.r10 = u->r10;
  	sys->regs.r9 = u->r9;
  	sys->regs.r8 = u->r8;
  	sys->regs.rax = u->rax;
  	sys->regs.rcx = u->rcx;
  	sys->regs.rdx = u->rdx;
  	sys->regs.rsi = u->rsi;
  	sys->regs.rdi = u->rdi;
  	sys->regs.orig_rax = u->orig_rax;
  	sys->regs.rip = u->rip;
  	sys->regs.cs = u->cs;
  	sys->regs.eflags = u->eflags;
  	sys->regs.rsp = u->rsp;
  	sys->regs.ss = u->ss;
  	sys->regs.fs_base = u->fs_base;
  	sys->regs.gs_base = u->gs_base;
	sys->regs.ds = u->ds;
	sys->regs.es = u->es;
	sys->regs.fs = u->fs;
	sys->regs.gs = u->gs;
#else
	sys->regs.ebx = u->ebx;
	sys->regs.ecx = u->ecx;
	sys->regs.edx = u->edx;
	sys->regs.esi = u->esi;
	sys->regs.edi = u->edi;
	sys->regs.ebp = u->ebp;
	sys->regs.eax = u->eax;
	sys->regs.xds = u->xds;
	sys->regs.xes = u->xes;
	sys->regs.xfs = u->xfs;
	sys->regs.xgs = u->xgs;
	sys->regs.orig_eax = u->orig_eax;
	sys->regs.eip = u->eip;
	sys->regs.xcs = u->xcs;
	sys->regs.eflags = u->eflags;
	sys->regs.esp = u->esp;
	sys->regs.xss = u->xss;
#endif
	sys->status = status;

	return sys;
}

void SUSY_Destroy(ST_SysCall *c){
	g_free(c);
	return;
}

void SUSY_Printf(ST_SysCall *c) {

	fprintf(stdout,"Syscall %s status %d\n",c->name,c->status);

#if __WORDSIZE == 64
	fprintf(stdout,"\torig_rax=0x%x;rax=0x%x;rbx=0x%x;rcx=0x%x\n",
		c->regs.orig_rax,c->regs.rax,c->regs.rbx,c->regs.rcx);	
	fprintf(stdout,"\tcs=0x%x;rip=0x%x;rsi=0x%x;rdi=0x%x\n",
		c->regs.cs,c->regs.rip,c->regs.rsi,c->regs.rdi);
#else
	fprintf(stdout,"\torig_eax=0x%x;eax=0x%x;ebx=0x%x;ecx=0x%x\n",
		c->regs.orig_eax,c->regs.eax,c->regs.ebx,c->regs.ecx);	
	fprintf(stdout,"\txcs=0x%x;eip=0x%x;esi=0x%x;edi=0x%x\n",
		c->regs.xcs,c->regs.eip,c->regs.esi,c->regs.edi);

#endif	
	return;
}
