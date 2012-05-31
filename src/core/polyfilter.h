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
#include <log4c.h>
#include "debug.h"
#include <sys/time.h>
#include "packetcontext.h"
#include "packetdecoder.h"
#include "connection.h"
#include "flowpool.h"
#include "userpool.h"
#include "usertable.h"
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

enum polyfilter_mode {
	POLYFILTER_MODE_NONCACHE = 0, // The engine is querying the cache.
	POLYFILTER_MODE_SOMECACHE, // The engine is querying the cache but with some trusted IP address.
	POLYFILTER_MODE_FULLCACHE // The engine is updating the cache.
};

static const char *polyfilter_modes_str [] = { "normal","hybrid","update"};

#define POLYVACCINE_FILTER_ENGINE_NAME "Polyvaccine filter engine"

struct ST_PolyFilter {
	int polyfilter_status;
	int pcapfd;
	int is_pcap_file;
	int when_pcap_done_exit;
	sigset_t sigmask;
	DBusConnection *bus;
	ST_Connection *conn;
	ST_UserTable *users;
	ST_FlowPool *flowpool;
	ST_MemoryPool *memorypool;
	ST_UserPool *userpool;
	ST_AuthorizedHost *hosts;
	ST_Forwarder *forwarder;
	GString *source;
	pcap_t *pcap;
	enum polyfilter_mode mode;	
	/* structs for manage dbus messages and packets */
        DBusWatch *local_watches[MAX_WATCHES];
        struct pollfd local_fds[MAX_WATCHES];
	int usepcap;
	/* time statistics */
	struct timeval starttime;
	struct timeval endtime;	
};

typedef struct ST_PolyFilter ST_PolyFilter;

void POFR_Init(void);
void POFR_Destroy(void);

void POFR_SetSource(char *source);
void POFR_SetExitOnPcap(int value);

void POFR_Stats(void);
void POFR_Start(void);
void POFR_Stop(void);
void POFR_StopAndExit(void);
void POFR_Run(void);


/* Service functions */
void POFR_SetStatisticsLevel(int level);
void POFR_SetMode(char *mode);
void POFR_SetLearningMode(void);

/* HTTP functions */
void POFR_AddToHTTPCache(int type,char *value);
void POFR_SetHTTPSourcePort(int port);
void POFR_SetForceAnalyzeHTTPPostData(int value);
void POFR_ShowUnknownHTTP(int value);
void POFR_SetInitialFlowsOnPool(int value);
void POFR_EnableAnalyzers(char *analyzers);
void POFR_SetHTTPStatisticsLevel(int level);

int32_t POFR_GetHTTPHeaderCacheHits(void);
int32_t POFR_GetHTTPHeaderCacheFails(void);
int32_t POFR_GetHTTPParameterCacheHits(void);
int32_t POFR_GetHTTPParameterCacheFails(void);

/* SIP Functions */
void POFR_SetSIPSourcePort(int port);

void POFR_AddTrustedUser(char *ip);
void POFR_RemoveTrustedUser(char *ip);

/* DDoS functions */
void POFR_SetDDoSStatisticsLevel(int level);
void POFR_SetDDoSSourcePort(int port);

#endif
