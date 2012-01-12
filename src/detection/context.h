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

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "debug.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>

struct ST_SharedContext {
	struct timeval total_latency;
        int isptracechild;
        pid_t child_pid;
	pid_t parent_pid;
        int signal;
        int virtualeip;
        int size;
        int incbytracer;
        int incbychild;
	int status;
	int request;
	int cpu_execed;
        void *memory;
};
typedef struct ST_SharedContext ST_SharedContext;

ST_SharedContext *COXT_GetContext(void);
ST_SharedContext *COXT_AttachContext(void);
void COXT_FreeContext(ST_SharedContext *c);
void COXT_Printf(ST_SharedContext *c);

#endif
