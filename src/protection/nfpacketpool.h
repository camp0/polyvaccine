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

#ifndef _NFPACKETPOOL_H_
#define _NFPACKETPOOL_H_

#include <sys/types.h>
#include <glib.h>
#include "flow.h"
#include "debug.h"

#define MAX_FLOWS_PER_POOL 1024 * 2 

struct ST_NfFlowPool {
	GSList *flows;
	int32_t total_releases;
	int32_t total_acquires;
	int32_t total_errors;
};

typedef struct ST_NfFlowPool ST_NfFlowPool;

ST_NfFlowPool *NFPO_Init(void);
void NFPO_Destroy(ST_NfFlowPool *p);
void NFPO_AddFlow(ST_NfFlowPool *p,ST_Flow *flow);
ST_Flow *NFPO_GetFlow(ST_NfFlowPool *p);	
int NFPO_GetNumberFlows(ST_NfFlowPool *p);
int NFPO_IncrementFlowPool(ST_NfFlowPool *p,int value);
int NFPO_DecrementFlowPool(ST_NfFlowPool *p,int value);
void NFPO_Stats(ST_NfFlowPool *p);
#endif
