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

#ifndef _POLYENGINE_H_
#define _POLYENGINE_H_

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
#include "httpcache.h"
#include "system.h"
#include "privatecallbacks.h"
#include "authorized.h"

enum {
        POLYENGINE_STATE_STOP = 0,
        POLYENGINE_STATE_RUNNING
} polyengine_states;

static const char *polyengine_states_str [] = { "stop","running"};

#define POLYVACCINE_AGENT_INTEFACE "polyvaccine.engine"
#define POLYVACCINE_FILTER_ENGINE_NAME "Filter engine"

struct ST_PolyEngine {
	int polyengine_status;
	int pcapfd;
	int is_pcap_file;
	int defaultport;
	DBusConnection *bus;
	ST_Connection *conn;
	ST_FlowPool *flowpool;
	ST_MemoryPool *memorypool;
	ST_HttpCache *httpcache;
	ST_AuthorizedHost *hosts;
	GString *source;
	pcap_t *pcap;
};

typedef struct ST_PolyEngine ST_PolyEngine;

void POEG_Init(void);
void POEG_Destroy(void);

void POEG_SetSource(char *source);
void POEG_SetSourcePort(int port);

void POEG_Stats(void);
void POEG_Start(void);
void POEG_Stop(void);
void POEG_StopAndExit(void);
void POEG_Run(void);

/* Service functions */
void POEG_AddToHttpCache(int type,char *value);

int32_t POEG_GetHttpHeaderCacheHits(void);
int32_t POEG_GetHttpHeaderCacheFails(void);
int32_t POEG_GetHttpParameterCacheHits(void);
int32_t POEG_GetHttpParameterCacheFails(void);

#endif
