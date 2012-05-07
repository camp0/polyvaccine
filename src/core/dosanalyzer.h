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
#include "genericflow.h"
#include "cache.h"
#include <sys/types.h>
#include <glib.h>
#include "debug.h"
#include "interfaces.h"

#define OVECCOUNT 30

struct ST_DoSAnalyzer{
	GHashTable *methods;
	GHashTable *parameters;
        pcre *expr_header;
        pcre_extra *pe_header;
        const char *errstr;
        int ovector[OVECCOUNT];

	/* configuration options */	
	int on_suspicious_header_break;
	int on_suspicious_parameter_break;
	int analyze_post_data;
	int show_unknown_http;
	
	/* statistics */
	int32_t suspicious_headers;
	int32_t suspicious_parameters;
	int32_t total_http_invalid_decode;
	int32_t total_suspicious_segments;
	int32_t total_valid_segments;
	int64_t total_http_bytes;
	int64_t total_http_segments;
};

typedef struct ST_DoSAnalyzer ST_DoSAnalyzer;

void *DSAZ_Init(void);
void *DSAZ_Destroy(void);
void *DSAZ_AnalyzeDSTPRequest(ST_Cache *c,ST_GenericFlow *f, int *ret);
void *DSAZ_Stats(void);
void *DSAZ_AnalyzeDummyDSTPRequest(ST_Cache *c, ST_GenericFlow *f);

#endif
