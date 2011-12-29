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

#ifndef _FLOW_H_
#define _FLOW_H_

#include <sys/types.h>

struct ST_Flow {
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;
	int id;
};

typedef struct ST_Flow ST_Flow;

static void FLOW_SetFlowId(ST_Flow *f,u_int32_t saddr,u_int16_t sport,u_int32_t daddr,u_int16_t dport){
	f->saddr = saddr;
	f->sport = sport;
	f->daddr = daddr;
	f->dport = dport;
	f->seq = 0;
	f->id = 0;
	return;
}

static void FLOW_SetSequenceNumber(ST_Flow *f,u_int32_t seq) { 
	f->seq = seq; 
	return;
};

#endif
