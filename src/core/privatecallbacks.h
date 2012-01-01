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
	{ "start",		NULL,"b",	PRCA_Method_StartEngine },
	{ "stop",		NULL,"b",	PRCA_Method_StopEngine },
	{ "setSource",		"s","b",	PRCA_Method_SetSource },
	{ "addAuthorizedHost",	"s","b",	PRCA_Method_AddAuthorizedHost }
};

#define MAX_PUBLIC_PROPERTIES 2
static ST_Callback ST_StaticPropertiesCallbacks [MAX_PUBLIC_PROPERTIES] = {
        { "state",              NULL,"s",       PRCA_Property_GetState },
        { "source",             "s","s",        PRCA_Property_GetSource }
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
        { "valid headers",              NULL,"i",       PRCA_Property_GetNumberValidHTTPHeaders },
        { "unknown headers",            NULL,"i",       PRCA_Property_GetNumberUnknownHTTPHeaders },
        { "valid parameters",           NULL,"i",      	PRCA_Property_GetNumberValidHTTPParameters  },
        { "unknown parameters",         NULL,"i",       PRCA_Property_GetNumberUnknownHTTPParameters },
        { "suspicious headers",         NULL,"i",       PRCA_Property_GetNumberSuspiciousHTTPHeaders },
        { "suspicious parameters",      NULL,"i",       PRCA_Property_GetNumberSuspiciousHTTPParameters },
        { "suspicious segments",      	NULL,"i",       PRCA_Property_GetNumberSuspiciousSegments },
        { "valid segments",      	NULL,"i",       PRCA_Property_GetNumberValidSegments }
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
        { "cache headers",              NULL,"i",       PRCA_Property_GetNumberHttpCacheHeaders },
        { "cache parameters",           NULL,"i",       PRCA_Property_GetNumberHttpCacheParameters },
        { "header hits",                NULL,"i",       PRCA_Property_GetNumberHttpHeaderHits  },
        { "header fails",               NULL,"i",       PRCA_Property_GetNumberHttpHeaderFails  },
        { "parameter hits",             NULL,"i",       PRCA_Property_GetNumberHttpParameterHits  },
        { "parameter fails",            NULL,"i",       PRCA_Property_GetNumberHttpParameterFails  }
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
        { "flows on pool",              NULL,"i",       PRCA_Property_GetTotalFlowsOnFlowPool },
        { "flow releases",              NULL,"i",       PRCA_Property_GetFlowPoolTotalReleases },
        { "flow acquires",              NULL,"i",       PRCA_Property_GetFlowPoolTotalAcquires },
        { "flow errors",              	NULL,"i",       PRCA_Property_GetFlowPoolTotalErrors },
	{ "segments on pool",		NULL,"i",	PRCA_Property_GetTotalSegmentOnMemoryPool },
	{ "segment releases",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalReleases },
	{ "segment acquires",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalAcquires },
	{ "segment errors",		NULL,"i",	PRCA_Property_GetMemoryPoolTotalErrors },
	{ "segment byte releases",	NULL,"x",	PRCA_Property_GetMemoryPoolTotalReleaseBytes },
	{ "segment byte acquires",	NULL,"x",	PRCA_Property_GetMemoryPoolTotalAcquireBytes }
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
                NULL,0,
                NULL,0,
                ST_StaticHTTPCachePropertiesCallbacks,MAX_HTTPCACHE_PROPERTIES,
        }
};


#endif
