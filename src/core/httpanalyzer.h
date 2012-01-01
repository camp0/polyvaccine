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

#include <pcre.h>
#include "httpflow.h"
#include "httpcache.h"
#include <sys/types.h>
#include <glib.h>
#include "debug.h"
#include "counter.h"

#define OVECCOUNT 30

struct ST_HttpAnalyzer{
	GHashTable *methods;
	GHashTable *parameters;
        pcre *expr_header;
        pcre_extra *pe_header;
        const char *errstr;
        int ovector[OVECCOUNT];	
	int on_suspicious_header_break;
	int on_suspicious_parameter_break;
	int32_t suspicious_headers;
	int32_t suspicious_parameters;
	int32_t total_suspicious_segments;
	int32_t total_valid_segments;
	int64_t total_http_bytes;
	int64_t total_http_segments;
};

typedef struct ST_HttpAnalyzer ST_HttpAnalyzer;

void HTAZ_Init(void);
void HTAZ_Destroy(void);
int HTAZ_AnalyzeHttpRequest(ST_HttpCache *c,ST_HttpFlow *f);
void HTAZ_AnalyzeDummyHttpRequest(ST_HttpCache *c, ST_HttpFlow *f);

/* Service functions */
int32_t HTAZ_GetNumberValidHTTPHeaders(void); 
int32_t HTAZ_GetNumberUnknownHTTPHeaders(void); 
int32_t HTAZ_GetNumberValidHTTPParameters(void);
int32_t HTAZ_GetNumberUnknownHTTPParameters(void);
int32_t HTAZ_GetNumberSuspiciousHTTPHeaders(void);
int32_t HTAZ_GetNumberSuspiciousHTTPParameters(void);
int32_t HTAZ_GetNumberSuspiciousSegments(void);
int32_t HTAZ_GetNumberValidSegments(void);
#endif
