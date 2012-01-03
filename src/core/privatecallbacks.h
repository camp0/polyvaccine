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

/* Properties functions */
void PRCA_Property_GetState(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StartEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StopEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddAuthorizedHost(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_ENGINE_METHODS 4
static ST_Callback ST_StaticEngineMethods[MAX_ENGINE_METHODS] = {
	{ "Start",		NULL,"b",	PRCA_Method_StartEngine },
	{ "Stop",		NULL,"b",	PRCA_Method_StopEngine },
	{ "SetSource",		"s","b",	PRCA_Method_SetSource },
	{ "AddAuthorizedHost",	"s","b",	PRCA_Method_AddAuthorizedHost }
};

#define MAX_PUBLIC_PROPERTIES 2
static ST_Callback ST_StaticPropertiesCallbacks [MAX_PUBLIC_PROPERTIES] = {
        { "State",              NULL,"s",       PRCA_Property_GetState },
        { "Source",             "s","s",        PRCA_Property_GetSource }
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

#define MAX_HTTP_PUBLIC_PROPERTIES 8
static ST_Callback ST_StaticHTTPPropertiesCallbacks [MAX_HTTP_PUBLIC_PROPERTIES] = {
        { "ValidHeaders",              NULL,"i",       PRCA_Property_GetNumberValidHTTPHeaders },
        { "UnknownHeaders",            NULL,"i",       PRCA_Property_GetNumberUnknownHTTPHeaders },
        { "ValidParameters",           NULL,"i",      	PRCA_Property_GetNumberValidHTTPParameters  },
        { "UnknownParameters",         NULL,"i",       PRCA_Property_GetNumberUnknownHTTPParameters },
        { "SuspiciousHeaders",         NULL,"i",       PRCA_Property_GetNumberSuspiciousHTTPHeaders },
        { "SuspiciousParameters",      NULL,"i",       PRCA_Property_GetNumberSuspiciousHTTPParameters },
        { "SuspiciousSegments",      	NULL,"i",       PRCA_Property_GetNumberSuspiciousSegments },
        { "ValidSegments",      	NULL,"i",       PRCA_Property_GetNumberValidSegments }
};

/* Functions related to the HTTP cache */
#define MAX_HTTPCACHE_PROPERTIES 6

void PRCA_Property_GetNumberHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpCacheParameters (DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpHeaderHits(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpHeaderFails(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpParameterHits(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberHttpParameterFails(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticHTTPCachePropertiesCallbacks [MAX_HTTPCACHE_PROPERTIES] = {
        { "CacheHeaders",              NULL,"i",       PRCA_Property_GetNumberHttpCacheHeaders },
        { "CacheParameters",           NULL,"i",       PRCA_Property_GetNumberHttpCacheParameters },
        { "HeaderHits",                NULL,"i",       PRCA_Property_GetNumberHttpHeaderHits  },
        { "HeaderFails",               NULL,"i",       PRCA_Property_GetNumberHttpHeaderFails  },
        { "ParameterHits",             NULL,"i",       PRCA_Property_GetNumberHttpParameterHits  },
        { "ParameterFails",            NULL,"i",       PRCA_Property_GetNumberHttpParameterFails  }
};

#define MAX_HTTPCACHE_METHODS 4 

void PRCA_Method_GetHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_GetHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_AddHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticHTTPCacheMethodCallbacks [MAX_HTTPCACHE_METHODS] = {
	{ "GetCacheHeaders",		NULL,"a(s)",	PRCA_Method_GetHttpCacheHeaders },
	{ "GetCacheParameters",		NULL,"a(s)",	PRCA_Method_GetHttpCacheParameters},
	{ "AddCacheHeader",		"s","b",	PRCA_Method_AddHttpCacheHeaders },
	{ "AddCacheParameter",		"s","b",	PRCA_Method_AddHttpCacheParameters}
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

#define MAX_CONNECTION_PUBLIC_PROPERTIES 10 
static ST_Callback ST_StaticConnectionPropertiesCallbacks [MAX_CONNECTION_PUBLIC_PROPERTIES] = {
        { "FlowsOnPool",              NULL,"i",       PRCA_Property_GetTotalFlowsOnFlowPool },
        { "FlowReleases",              NULL,"i",       PRCA_Property_GetFlowPoolTotalReleases },
        { "FlowAcquires",              NULL,"i",       PRCA_Property_GetFlowPoolTotalAcquires },
        { "FlowErrors",              	NULL,"i",       PRCA_Property_GetFlowPoolTotalErrors },
	{ "SegmentsOnPool",		NULL,"i",	PRCA_Property_GetTotalSegmentOnMemoryPool },
	{ "SegmentReleases",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalReleases },
	{ "SegmentAcquires",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalAcquires },
	{ "SegmentErrors",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalErrors },
	{ "SegmentByteReleases",	NULL,"x",	PRCA_Property_GetMemoryPoolTotalReleaseBytes },
	{ "SegmentByteAcquires",	NULL,"x",	PRCA_Property_GetMemoryPoolTotalAcquireBytes }
};

void PRCA_Method_IncreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_DecreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_IncreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_DecreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_CONNECTION_PUBLIC_METHODS 4
static ST_Callback ST_StaticConnectionMethodCallbacs [MAX_CONNECTION_PUBLIC_METHODS] = {
	{ "IncreaseMemoryPool",		"i","b",	PRCA_Method_IncreaseMemoryPool },
	{ "DecreaseMemoryPool",		"i","b",	PRCA_Method_DecreaseMemoryPool },
	{ "IncreaseFlowPool",		"i","b",	PRCA_Method_IncreaseFlowPool },
	{ "DecreaseFlowPool",		"i","b",	PRCA_Method_DecreaseFlowPool }
};

#define MAX_PUBLIC_INTERFACES 4

static ST_Interface ST_PublicInterfaces [MAX_PUBLIC_INTERFACES] = {
        { POLYVACCINE_AGENT_INTERFACE,
                ST_StaticEngineMethods,MAX_ENGINE_METHODS,
		NULL,0,
               	ST_StaticPropertiesCallbacks, MAX_PUBLIC_PROPERTIES 
        },
        { POLYVACCINE_AGENT_CONNECTION_INTERFACE,
                ST_StaticConnectionMethodCallbacs,MAX_CONNECTION_PUBLIC_METHODS,
                NULL,0,
                ST_StaticConnectionPropertiesCallbacks,MAX_CONNECTION_PUBLIC_PROPERTIES
        },
	{ POLYVACCINE_AGENT_HTTP_INTERFACE,
		NULL,0,
		NULL,0,
		ST_StaticHTTPPropertiesCallbacks,MAX_HTTP_PUBLIC_PROPERTIES
	},
        { POLYVACCINE_AGENT_HTTPCACHE_INTERFACE,
                ST_StaticHTTPCacheMethodCallbacks,MAX_HTTPCACHE_METHODS,
                NULL,0,
                ST_StaticHTTPCachePropertiesCallbacks,MAX_HTTPCACHE_PROPERTIES,
        }
};


#endif
