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

#ifndef _MEMORYPOOL_H_
#define _MEMORYPOOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "memory.h"
#include "debug.h"

#define MAX_MEMORY_SEGMENTS_PER_POOL 1024 * 2 

struct ST_MemoryPool {
	GSList *mem;
	int32_t total_releases;
	int32_t total_acquires;
	int32_t total_errors;
	int64_t total_release_bytes;
	int64_t total_acquire_bytes;
};

typedef struct ST_MemoryPool ST_MemoryPool;

/**
 * Inits the memory pool 
 * 
 * @returns a ST_MemoryPool alloclated
 */
ST_MemoryPool *MEPO_Init(void);

/**
 * Destroy the memory pool 
 * 
 * @param ST_MemoryPool to free
 */
void MEPO_Destroy(ST_MemoryPool *mp);

void MEPO_AddMemorySegment(ST_MemoryPool *mp,ST_MemorySegment *m);
ST_MemorySegment *MEPO_GetMemorySegment(ST_MemoryPool *mp);	
int MEPO_GetNumberMemorySegments(ST_MemoryPool *mp);
int MEPO_IncrementMemoryPool(ST_MemoryPool *mp,int value);
int MEPO_DecrementMemoryPool(ST_MemoryPool *mp,int value);
void MEPO_Stats(ST_MemoryPool *mp);

/// TODO
/// Need a function which reallocates the memory segments on the memorypool


#endif
