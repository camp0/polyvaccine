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

#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <seccomp.h>
#include "segment.h"
#include "sharedcontext.h"
#include "interfaces.h"
#include <stdlib.h>
#include <sched.h>

struct ST_Sandbox {
	/* Info shared with the child */
	ST_ExecutableSegment *seg;	
	ST_SharedContext *ctx;
	int total_executed;
	int total_shellcodes;
	int total_bytes_process;
	int debug_level;
};
typedef struct ST_Sandbox ST_Sandbox;

enum {
	SABX_SHELLCODE_DETECTED = 0,
	SABX_SHELLCODE_CLEAN,
	SABX_SHELLCODE_CONTINUE
}sabx_status;

ST_Sandbox *SABX_Init(void);
void SABX_Destroy(ST_Sandbox *sx);
void SABX_Statistics(ST_Sandbox *sx);
int SABX_AnalyzeSegmentMemory(ST_Sandbox *sx,char *buffer, int size, ST_TrustOffsets *t_off);

#endif
