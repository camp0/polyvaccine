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

#ifndef _MEMORY_H_
#define _MEMORY_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include "debug.h"
#include <sys/types.h>
#include <glib.h>

#define MAX_SEGMENT_SIZE 512

struct ST_MemorySegment {
	unsigned char *mem;
	int virtual_size;	
	int real_size;
};

typedef struct ST_MemorySegment ST_MemorySegment;

ST_MemorySegment *MESG_Init(void);
ST_MemorySegment *MESG_InitWithSize(int size);
void MESG_Destroy(ST_MemorySegment *m);
void MESG_Reset(ST_MemorySegment *m);
void MESG_UpdateSize(ST_MemorySegment *m,int size);
void MESG_AppendPayload(ST_MemorySegment *m,unsigned char *payload,int size);
void MESG_AppendPayloadNew(ST_MemorySegment *m,unsigned char *payload,int size);

#endif
