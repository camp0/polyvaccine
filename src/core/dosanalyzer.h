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

#ifndef _DOSANALYZER_H_
#define _DOSANALYZER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcre.h>
#include <log4c.h>
#include "user.h"
#include "genericflow.h"
#include "cache.h"
#include "graphcache.h"
#include "pathcache.h"
#include <sys/types.h>
#include <glib.h>
#include "debug.h"
#include "interfaces.h"

#define SAMPLE_TIME 60 * 24 // minutes
#define OVECCOUNT 30

struct ST_DoSAnalyzer{
        pcre *expr_header;
        pcre_extra *pe_header;
        const char *errstr;
        int ovector[OVECCOUNT];

	ST_GraphCache *graphcache;
	ST_PathCache *pathcache;
	/* configuration options */	
	int statistics_level;
	
	/* statistics */
	int32_t total_valid_links;
	int32_t total_invalid_links;
	int32_t total_exist_uri;
	int32_t total_nonexist_uri;
	int32_t total_exist_links;
	int32_t total_nonexist_links;
	int64_t total_http_bytes;
	int64_t total_http_request;
	int64_t http_request_per_minute;

	/* statistics related to the flows */
	struct timeval prev_sample;
	struct timeval curr_sample;

	int32_t request_per_minute[SAMPLE_TIME];
	int32_t flows_per_minute[SAMPLE_TIME];
};

typedef struct ST_DoSAnalyzer ST_DoSAnalyzer;

void *DSAZ_Init(void);
void *DSAZ_Destroy(void);
void *DSAZ_AnalyzeHTTPRequest(ST_User *user,ST_GenericFlow *f, int *ret);
void *DSAZ_Stats(void);
void *DSAZ_AnalyzeDummyHTTPRequest(ST_User *user, ST_GenericFlow *f);

void DSAZ_SetGraphStatisticsLevel(int level);
#endif
