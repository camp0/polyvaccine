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
 * Written by Luis Campo Giralte <luis.camp0.209@gmail.com> 2009 
 *
 */

#ifndef _POLYFILTER_H_
#define _POLYFILTER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dbus/dbus.h>
#include <stdio.h>
#include <glib.h>
#include "debug.h"
#include <sys/time.h>
#include "packetcontext.h"
#include "packetdecoder.h"
#include "connection.h"
#include "flowpool.h"
#include "memorypool.h"
#include "cache.h"
#include "forwarder.h"
#include "system.h"
#include "privatecallbacks.h"
#include "trustoffset.h"
#include "authorized.h"
#include "banner.h"

enum {
        POLYFILTER_STATE_STOP = 0,
        POLYFILTER_STATE_RUNNING
} polyfilter_states;

static const char *polyfilter_states_str [] = { "stop","running"};

#define POLYVACCINE_FILTER_ENGINE_NAME "Polyvaccine filter engine"

struct ST_PolyFilter {
	int polyfilter_status;
	int pcapfd;
	int is_pcap_file;
	int defaultport;
	DBusConnection *bus;
	ST_Connection *conn;
	ST_FlowPool *flowpool;
	ST_MemoryPool *memorypool;
	ST_Cache *httpcache;
	ST_Cache *sipcache;
	ST_AuthorizedHost *hosts;
	ST_Forwarder *forwarder;
	GString *source;
	pcap_t *pcap;
};

typedef struct ST_PolyFilter ST_PolyFilter;

void POFR_Init(void);
void POFR_Destroy(void);

void POFR_SetSource(char *source);
void POFR_SetSourcePort(int port);
void POFR_SetForceAnalyzeHTTPPostData(int value);
void POFR_ShowUnknownHTTP(int value);

void POFR_Stats(void);
void POFR_Start(void);
void POFR_Stop(void);
void POFR_StopAndExit(void);
void POFR_Run(void);

/* Service functions */
void POFR_SetLearningMode(void);
void POFR_AddToHTTPCache(int type,char *value);

int32_t POFR_GetHTTPHeaderCacheHits(void);
int32_t POFR_GetHTTPHeaderCacheFails(void);
int32_t POFR_GetHTTPParameterCacheHits(void);
int32_t POFR_GetHTTPParameterCacheFails(void);

#endif