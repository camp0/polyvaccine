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

#ifndef _GENERICFLOW_H_
#define _GENERICFLOW_H_

#include "pathcache.h"
#include "memory.h"
#include <sys/types.h>

struct ST_GenericFlow {
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t protocol;

	int32_t total_bytes;
        int32_t total_packets;

	short is_analyzed;
	short direction;
	short aborted;
	short tcp_state_prev;
	short tcp_state_curr;

	struct timeval arrive_time;
	struct timeval current_time;
	struct timeval last_uri_seen; // used on the dosanalyzer;
	ST_MemorySegment *memory;
	
	char *lasturi; // This parameter is used to know the last URI visited for the dosanalyzer
	int lasturi_id;

	ST_PathNode *path;	
} __attribute__((packed));

typedef struct ST_GenericFlow ST_GenericFlow;

#define FLOW_FORW 0
#define FLOW_BACK 1

static void GEFW_SetFlowId(ST_GenericFlow *f,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport){
	f->saddr = saddr;
	f->sport = sport;
	f->daddr = daddr;
	f->dport = dport;
	f->protocol = protocol;
	return;
}
static void GEFW_Reset(ST_GenericFlow *f) {
	f->is_analyzed = 0; 
	f->total_bytes = 0;f->total_packets= 0;
	f->arrive_time.tv_sec = 0;f->arrive_time.tv_usec = 0;
	f->current_time.tv_sec = 0;f->current_time.tv_usec = 0;
	f->last_uri_seen.tv_sec = 0;f->last_uri_seen.tv_usec = 0;
	f->tcp_state_prev = 0; // Corresponds to TCP_CLOSE state
	f->tcp_state_curr = 0;
	f->aborted = 0;
	f->direction = FLOW_FORW;
	f->memory = NULL;
	f->lasturi = NULL;
	f->lasturi_id = 0;
	f->path = NULL;
	return;
};

static void GEFW_SetMemorySegment(ST_GenericFlow *f,ST_MemorySegment *m) { f->memory = m;};

static void GEFW_SetArriveTime(ST_GenericFlow *f,struct timeval *t) { 
	f->arrive_time.tv_sec = t->tv_sec;f->arrive_time.tv_usec = t->tv_usec;
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
};

static void GEFW_UpdateTime(ST_GenericFlow *f,struct timeval *t) {
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
}

static void GEFW_Destroy(ST_GenericFlow *f){
	if(f){
		g_free(f);
		f = NULL;
	}
}
#endif
