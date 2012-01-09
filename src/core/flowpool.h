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

#ifndef _FLOWPOOL_H_
#define _FLOWPOOL_H_

#include <sys/types.h>
#include <glib.h>
#include "httpflow.h"

#define MAX_FLOWS_PER_POOL 1024 * 16 

struct ST_FlowPool {
	GSList *flows;
	int32_t total_releases;
	int32_t total_acquires;
	int32_t total_errors;
};

typedef struct ST_FlowPool ST_FlowPool;

ST_FlowPool *FLPO_Init(void);
void FLPO_Destroy(ST_FlowPool *p);
void FLPO_AddFlow(ST_FlowPool *p,ST_HttpFlow *flow);
ST_HttpFlow *FLPO_GetFlow(ST_FlowPool *p);	
int FLPO_GetNumberFlows(ST_FlowPool *p);
int FLPO_IncrementFlowPool(ST_FlowPool *p,int value);
int FLPO_DecrementFlowPool(ST_FlowPool *p,int value);
void FLPO_Stats(ST_FlowPool *p);
#endif
