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

#ifndef _HTTPANALYZER_H_
#define _HTTPANALYZER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <pcre.h>
#include <log4c.h>
#include "genericflow.h"
#include "cache.h"
#include "user.h"
#include "trustoffset.h"
#include <sys/types.h>
#include <glib.h>
#include "debug.h"
#include "interfaces.h"
#include "counter.h"
#include "polydbus.h"
#include "httpsignalbalancer.h"

#define OVECCOUNT 30

struct ST_HTTPAnalyzer{
	GHashTable *methods;
	GHashTable *parameters;
        pcre *expr_header;
        pcre_extra *pe_header;
        const char *errstr;
	ST_TrustOffsets *t_off;
        int ovector[OVECCOUNT];
	ST_Cache *httpcache;
	ST_HTTPSignalBalancer *sb;
	/* configuration options */	
	int on_suspicious_header_break;
	int on_suspicious_parameter_break;
	int analyze_post_data;
	int show_unknown_http;
	int statistics_level;
	
	/* statistics */
	int32_t suspicious_headers;
	int32_t suspicious_parameters;
	int32_t total_http_invalid_decode;
	int32_t total_suspicious_segments;
	int32_t total_valid_segments;
	int64_t total_http_bytes;
	int64_t total_http_segments;
};

typedef struct ST_HTTPAnalyzer ST_HTTPAnalyzer;

void *HTAZ_Init(void);
void *HTAZ_Destroy(void);
void *HTAZ_AnalyzeHTTPRequest(ST_User *user,ST_GenericFlow *f, int *ret);
void *HTAZ_Stats(void);
void *HTAZ_AnalyzeDummyHTTPRequest(ST_User *user, ST_GenericFlow *f);
void *HTAZ_NotifyCorrect(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq);
void *HTAZ_NotifyWrong(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq);
void HTAZ_SetForceAnalyzeHTTPPostData(int value);
void HTAZ_ShowUnknownHTTP(int value);
void HTAZ_SetStatisticsLevel(int level);

ST_Cache *HTAZ_GetCache(void);

ST_TrustOffsets *HTAZ_GetTrustOffsets(void);

/* Service functions */
int32_t HTAZ_GetNumberValidHTTPHeaders(void); 
int32_t HTAZ_GetNumberUnknownHTTPHeaders(void); 
int32_t HTAZ_GetNumberValidHTTPParameters(void);
int32_t HTAZ_GetNumberUnknownHTTPParameters(void);
int32_t HTAZ_GetNumberSuspiciousHTTPHeaders(void);
int32_t HTAZ_GetNumberSuspiciousHTTPParameters(void);
int32_t HTAZ_GetNumberSuspiciousSegments(void);
int32_t HTAZ_GetNumberValidSegments(void);

void HTAZ_AddHeaderToCache(char *value,int type);
void HTAZ_AddParameterToCache(char *value,int type);
int HTAZ_GetNumberHeaders(void);
int HTAZ_GetNumberParameters(void);
int32_t HTAZ_GetHeaderHits(void);
int32_t HTAZ_GetHeaderFails(void);
int32_t HTAZ_GetParameterHits(void);
int32_t HTAZ_GetParameterFails(void);
int32_t HTAZ_GetCacheMemorySize(void);

/* for balance the signals to the detection engine */
void HTAZ_AddDetectorNode(char *interface,char *name);

#endif
