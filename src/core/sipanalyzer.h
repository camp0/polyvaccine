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

#ifndef _SIPANALYZER_H_
#define _SIPANALYZER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <pcre.h>
#include "user.h"
#include "genericflow.h"
#include "cache.h"
#include "trustoffset.h"
#include <sys/types.h>
#include <glib.h>
#include "counter.h"
#include "interfaces.h"

#define OVECCOUNT 30

struct ST_SIPAnalyzer{
	GHashTable *methods;
	GHashTable *parameters;
        pcre *expr_header;
        pcre_extra *pe_header;
        const char *errstr;
	ST_TrustOffsets *t_off;
        int ovector[OVECCOUNT];
	ST_Cache *sipcache;
	/* configuration options */	
	int on_suspicious_header_break;
	int on_suspicious_parameter_break;
	int analyze_sdp_data;
	int show_unknown_sip;
	
	/* statistics */
	int32_t suspicious_headers;
	int32_t suspicious_parameters;
	int32_t total_suspicious_segments;
	int32_t total_valid_segments;
	int64_t total_sip_bytes;
	int64_t total_sip_segments;
};

typedef struct ST_SIPAnalyzer ST_SIPAnalyzer;

void *SPAZ_Init(void);
void *SPAZ_Destroy(void);
void *SPAZ_AnalyzeSIPRequest(ST_User *user,ST_GenericFlow *f, int *ret);
void *SPAZ_Stats(void);
void *SPAZ_AnalyzeDummySIPRequest(ST_User *user,ST_GenericFlow *f);
void SPAZ_SetForceAnalyzeSIPSdpData(int value);
void SPAZ_ShowUnknownSIP(int value);

ST_TrustOffsets *SPAZ_GetTrustOffsets(void);

/* Service functions */
int32_t SPAZ_GetNumberValidSIPHeaders(void); 
int32_t SPAZ_GetNumberUnknownSIPHeaders(void); 
int32_t SPAZ_GetNumberValidSIPParameters(void);
int32_t SPAZ_GetNumberUnknownSIPParameters(void);
int32_t SPAZ_GetNumberSuspiciousSIPHeaders(void);
int32_t SPAZ_GetNumberSuspiciousSIPParameters(void);
int32_t SPAZ_GetNumberSuspiciousSegments(void);
int32_t SPAZ_GetNumberValidSegments(void);
#endif
