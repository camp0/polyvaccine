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

#ifndef _PRIVATECALLBACKS_H_
#define _PRIVATECALLBACKS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "callbacks.h"
#include <glib.h>
#include "polydbus.h"
#include <dbus/dbus.h>
#include "debug.h"

#define POLYVACCINE_AGENT_INTERFACE "polyvaccine.engine"
#define POLYVACCINE_AGENT_HTTP_INTERFACE POLYVACCINE_AGENT_INTERFACE ".http"
#define POLYVACCINE_AGENT_HTTPCACHE_INTERFACE POLYVACCINE_AGENT_INTERFACE ".httpcache"
#define POLYVACCINE_AGENT_CONNECTION_INTERFACE POLYVACCINE_AGENT_INTERFACE ".connection"

/* Properties functions */
void PRCA_Property_GetState(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StartEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StopEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddAuthorizedHost(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticEngineMethods[] = {
	{ 
		.name 	= 	"Start",
		.in 	=	NULL,
		.out 	=	"b",
		.func	= 	PRCA_Method_StartEngine 
	},
	{ 
		.name 	= 	"Stop",
		.in	=	NULL,
		.out	=	"b",
		.func	=	PRCA_Method_StopEngine 
	},
	{	
		.name	= 	"SetSource",
		.in	=	"s",
		.out	=	"b",
		.func	=	PRCA_Method_SetSource
	},
	{
		.name	=	"AddAuthorizedHost",
		.in	=	"s",
		.out	=	"b",
		.func	=	PRCA_Method_AddAuthorizedHost		
	},
	{} 
};

static ST_Callback ST_StaticPropertiesCallbacks [] = {
        { 
		.name	=	"State",
		.in	=       NULL,
		.out	=	"s",       
		.func	=	PRCA_Property_GetState 
	},
        { 
		.name	=	"Source",
		.in	=       "s",
		.out	=	"s",
		.func	=        PRCA_Property_GetSource 
	},
	{}
};

/* Functions related to the HTTP analyzer */
void PRCA_Property_GetNumberValidHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberUnknownHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data); 
void PRCA_Property_GetNumberValidHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberUnknownHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberSuspiciousHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberSuspiciousHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberSuspiciousSegments(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberValidSegments(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticHTTPPropertiesCallbacks [] = {
        { 
		.name	=	"ValidHeaders",
		.in	=	NULL,
		.out	=	"i",
		.func	= 	PRCA_Property_GetNumberValidHTTPHeaders 
	},
	{
		.name	=	"UnknownHeaders",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetNumberUnknownHTTPHeaders
	},
	{	
		.name	=	"ValidParameters",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetNumberValidHTTPParameters
	},
        { 
		.name	=	"UnknownParameters",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberUnknownHTTPParameters 
	},
        { 
		.name	=	"SuspiciousHeaders",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetNumberSuspiciousHTTPHeaders 
	},
        { 
		.name	=	"SuspiciousParameters",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberSuspiciousHTTPParameters 
	},
        { 
		.name	=	"SuspiciousSegments",
		.in	=      	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberSuspiciousSegments 
	},
        { 
		.name	=	"ValidSegments",
		.in	=      	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberValidSegments 
	}, 
	{}
};

/* Functions related to the HTTP cache */
void PRCA_Property_GetNumberHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpCacheParameters (DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpHeaderHits(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpHeaderFails(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpParameterHits(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpParameterFails(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticHTTPCachePropertiesCallbacks [] = {
        { 
		.name	=	"CacheHeaders",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpCacheHeaders 
	},
        { 
		.name 	=	"CacheParameters",
		.in	=       NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpCacheParameters 
	},
        { 
		.name	=	"HeaderHits",
		.in	=       NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpHeaderHits  
	},
        { 
		.name	=	"HeaderFails",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpHeaderFails  
	},
        { 
		.name	=	"ParameterHits",
		.in	=       NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpParameterHits  
	},
        { 
		.name	=	"ParameterFails",
		.in	=       NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetNumberHttpParameterFails  
	},
	{}
};

void PRCA_Method_GetHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_GetHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticHTTPCacheMethodCallbacks [] = {
	{ 
		.name	=	"GetCacheHeaders",
		.in	=	NULL,
		.out	=	"a(s)",
		.func	=	PRCA_Method_GetHttpCacheHeaders 
	},
	{ 
		.name	=	"GetCacheParameters",
		.in	=	NULL,
		.out	=	"a(s)",
		.func	=	PRCA_Method_GetHttpCacheParameters
	},
	{ 
		.name	=	"AddCacheHeader",
		.in	=	"s",
		.out	=	"b",
		.func	=	PRCA_Method_AddHttpCacheHeaders 
	},
	{ 
		.name	=	"AddCacheParameter",
		.in	=	"s",
		.out	=	"b",
		.func	=	PRCA_Method_AddHttpCacheParameters
	},
	{}
};

/* Functions related to the connection manager */

void PRCA_Property_GetFlowPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetFlowPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetFlowPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetMemoryPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetMemoryPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetMemoryPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetMemoryPoolTotalReleaseBytes(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetMemoryPoolTotalAcquireBytes(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalFlowsOnFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalSegmentOnMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticConnectionPropertiesCallbacks [] = {
        { 
		.name	=	"FlowsOnPool",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetTotalFlowsOnFlowPool 
	},
        { 
		.name	=	"FlowReleases",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetFlowPoolTotalReleases 
	},
        { 
		.name	=	"FlowAcquires",
		.in	=       NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetFlowPoolTotalAcquires 
	},
	{ 
		.name	=	"FlowErrors",
		.in	=	NULL,
		.out	=	"i",
		.func	=       PRCA_Property_GetFlowPoolTotalErrors 
	},
	{ 
		.name	=	"SegmentsOnPool",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetTotalSegmentOnMemoryPool 
	},
	{ 
		.name	=	"SegmentReleases",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetMemoryPoolTotalReleases 
	},
	{ 
		.name	=	"SegmentAcquires",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetMemoryPoolTotalAcquires 
	},
	{ 
		.name	=	"SegmentErrors",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetMemoryPoolTotalErrors 
	},
	{ 
		.name	=	"SegmentByteReleases",
		.in	=	NULL,
		.out	=	"x",
		.func	=	PRCA_Property_GetMemoryPoolTotalReleaseBytes 
	},
	{ 
		.name	=	"SegmentByteAcquires",	
		.in	=	NULL,
		.out	=	"x",
		.func	=	PRCA_Property_GetMemoryPoolTotalAcquireBytes 
	},
	{}
};

void PRCA_Method_IncreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_DecreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_IncreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_DecreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticConnectionMethodCallbacks [] = {
	{ 
		.name	=	"IncreaseMemoryPool",
		.in	=	"i",
		.out	=	"b",
		.func	=	PRCA_Method_IncreaseMemoryPool 
	},
	{ 
		.name	=	"DecreaseMemoryPool",
		.in	=	"i",
		.out	=	"b",
		.func	=	PRCA_Method_DecreaseMemoryPool 
	},
	{ 
		.name	=	"IncreaseFlowPool",
		.in	=	"i",
		.out	=	"b",
		.func	=	PRCA_Method_IncreaseFlowPool 
	},
	{ 
		.name	=	"DecreaseFlowPool",
		.in	=	"i",
		.out	=	"b",
		.func	=	PRCA_Method_DecreaseFlowPool 
	},
	{}
};

static ST_Interface ST_PublicInterfaces [] = {
        { 
		.name		=	POLYVACCINE_AGENT_INTERFACE,
		.methods 	= 	ST_StaticEngineMethods,
		.signals 	= 	NULL,
		.properties 	= 	ST_StaticPropertiesCallbacks	
	},
	{	
		.name		= 	POLYVACCINE_AGENT_HTTP_INTERFACE,
		.methods	=	NULL,
		.signals	=	NULL,
		.properties	=	ST_StaticHTTPPropertiesCallbacks
	},
	{
		.name		=	POLYVACCINE_AGENT_HTTPCACHE_INTERFACE,
		.methods	=	ST_StaticHTTPCacheMethodCallbacks,
		.signals	=	NULL,
		.properties	=	ST_StaticHTTPCachePropertiesCallbacks	
	},
	{
		.name		=	POLYVACCINE_AGENT_CONNECTION_INTERFACE,
		.methods	=	ST_StaticConnectionMethodCallbacks,	
		.signals	=	NULL,
		.properties	=	ST_StaticConnectionPropertiesCallbacks	
	},
	{}
};


#endif
