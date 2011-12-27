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

#ifndef _HTTPFLOW_H_
#define _HTTPFLOW_H_

#include "memory.h"
#include <sys/types.h>

struct ST_HttpFlow {
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;

	int32_t total_bytes;
        int32_t total_packets;

	struct timeval arrive_time;
	struct timeval current_time;
	ST_MemorySegment *memhttp;	
};

typedef struct ST_HttpFlow ST_HttpFlow;

static void HTLF_SetFlowId(ST_HttpFlow *f,u_int32_t saddr,u_int16_t sport,u_int32_t daddr,u_int16_t dport){
	f->saddr = saddr;
	f->sport = sport;
	f->daddr = daddr;
	f->dport = dport;
	return;
}
static void HTFL_Reset(ST_HttpFlow *f) { 
	f->total_bytes = 0;f->total_packets= 0;
	f->arrive_time.tv_sec = 0;f->arrive_time.tv_usec = 0;
	f->current_time.tv_sec = 0;f->current_time.tv_usec = 0;
	f->memhttp = NULL; 
	return;
};

static void HTFL_SetMemorySegment(ST_HttpFlow *f,ST_MemorySegment *m) { f->memhttp = m;};

static void HTFL_SetArriveTime(ST_HttpFlow *f,struct timeval *t) { 
	f->arrive_time.tv_sec = t->tv_sec;f->arrive_time.tv_usec = t->tv_usec;
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
};

static void HTFL_UpdateTime(ST_HttpFlow *f,struct timeval *t) {
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
}

#endif
