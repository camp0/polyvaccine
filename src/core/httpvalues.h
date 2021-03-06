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

#ifndef _HTTPVALUES_H_
#define _HTTPVALUES_H_

#define CRLF "\r\n"

struct ST_HTTPField {
	int nfield;
	char *name;
	int32_t matchs;
	int have_data;
	int check_cache;
};
typedef struct ST_HTTPField ST_HTTPField;

enum {
	/* Header types */
	HTTP_HEADER_GET  = 0,
	HTTP_HEADER_POST,
	HTTP_HEADER_OPTIONS,
	HTTP_HEADER_HEAD,
	HTTP_HEADER_CONNECT,
	HTTP_HEADER_PUT,
	HTTP_HEADER_DELETE,
	HTTP_HEADER_TRACE,
	HTTP_HEADER_UNKNOWN
};

static ST_HTTPField ST_HTTPTypeHeaders[] = {
	{ 
		.nfield		=	HTTP_HEADER_GET,		
		.name		=	"GET",		
		.matchs		=	0,
		.have_data	=	0,
		.check_cache	=	TRUE
	},
        {
                .nfield         =       HTTP_HEADER_POST,
                .name           =       "POST",
                .matchs         =       0,
                .have_data      =       TRUE,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_OPTIONS,
                .name           =       "OPTIONS",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_HEAD,
                .name           =      	"HEAD",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_CONNECT,
                .name           =       "CONNECT",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_PUT,
                .name           =       "PUT",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_DELETE,
                .name           =       "DELETE",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_TRACE,
                .name           =       "TRACE",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
        {
                .nfield         =       HTTP_HEADER_UNKNOWN,
                .name           =       "UNKNOWN",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE
        },
	{}
};

enum {
	/* Common headers */
	HTTP_FIELD_CACHE_CONTROL = 0,
	HTTP_FIELD_CONNECTION,
	HTTP_FIELD_DATE,
	HTTP_FIELD_PRAGMA,
	HTTP_FIELD_TRANSFER_ENCONDING,
	HTTP_FIELD_UPGRADE,
	HTTP_FIELD_VIA,
	/* Request headers */
	HTTP_FIELD_ACCEPT,
	HTTP_FIELD_ACCEPT_CHARSET,
	HTTP_FIELD_ACCEPT_ENCODING,
	HTTP_FIELD_ACCEPT_LANGUAGE,
	HTTP_FIELD_ACCEPT_RANGES,
	HTTP_FIELD_AUTHORIZATION,
	HTTP_FIELD_FROM,
	HTTP_FIELD_AGE,
	HTTP_FIELD_HOST,
	HTTP_FIELD_IF_MODIFIED_SINCE,
	HTTP_FIELD_IF_MATCH,
	HTTP_FIELD_IF_NONE_MATCH,
	HTTP_FIELD_IF_RANGE,
	HTTP_FIELD_IF_UNMODIFIED_SINCE,
	HTTP_FIELD_MAX_FORWARDS,
	HTTP_FIELD_PROXY_AUTHORIZATION,
	HTTP_FIELD_PROXY_AUTENTICATE,
	HTTP_FIELD_RANGE,
	HTTP_FIELD_REFERER,
	HTTP_FIELD_RETRY_AFTER,
	HTTP_FIELD_USER_AGENT,
	HTTP_FIELD_SERVER,
	/* Entity headers */
	HTTP_FIELD_ALLOW,
	HTTP_FIELD_CONTENT_BASE,
	HTTP_FIELD_CONTENT_ENCODING,
	HTTP_FIELD_CONTENT_LANGUAGE,
	HTTP_FIELD_CONTENT_LENGTH,
	HTTP_FIELD_CONTENT_LOCATION,
	HTTP_FIELD_CONTENT_MD5,
	HTTP_FIELD_CONTENT_RANGE,
	HTTP_FIELD_CONTENT_TYPE,
	HTTP_FIELD_CONTENT_ETAG,
	HTTP_FIELD_CONTENT_EXPIRES,
	HTTP_FIELD_CONTENT_LAST_MODIFIED,
	/* Other headers */
	HTTP_FIELD_COOKIE,	
	HTTP_FIELD_COOKIE2,	
	HTTP_FIELD_UA_CPU,	
	HTTP_FIELD_UA_OS,	
	HTTP_FIELD_X_FORWARDED_FOR,
	HTTP_FIELD_KEEP_ALIVE,	
	HTTP_FIELD_CLIENT_IP,
	HTTP_FIELD_X_FLASH_VERSION,
	HTTP_FIELD_UNLESS_MODIFIED_SINCE,	
	HTTP_FIELD_TE,
	HTTP_FIELD_WEFERER,	
	HTTP_FIELD_EXPECT,
	HTTP_FIELD_CONTENT_DISPOSITION,
	HTTP_FIELD_X_MOZ,
	HTTP_FIELD_X_ICAP_VERSION,
	HTTP_FIELD_NPFREFR,
	HTTP_FIELD_X_VERMEER_CONTENT_TYPE, /* campo raro del POST */
	HTTP_FIELD_MIME_VERSION,	/* del POST */

	/* Case sensitive headers */
	HTTP_FIELD_CONTENT_TYPE_1,
	HTTP_FIELD_CONTENT_TYPE_2,
	HTTP_FIELD_CONTENT_LENGTH_1,
	HTTP_FIELD_CONTENT_LENGTH_2,
	HTTP_FIELD_USER_AGENT_1,
	HTTP_FIELD_USER_AGENT_2,

	/* Other fields */
	HTTP_FIELD_PROXY_CONNECTION,
	HTTP_FIELD_CONTENT_FILTER_HELPER,

	HTTP_FIELD_UNKNOWN // just for counting pourposes
};

/* Notas de Campos:
 *
 * X-BlueCoat-Via: Usado por el Firewall Bluecoat para ocultar info.
 * X-McProxyFilter: Usado por el Firewall de Mac Affee para ocultar info.
 *
 */ 
static ST_HTTPField ST_HTTPFields [] = {
	{ HTTP_FIELD_CACHE_CONTROL,		"Cache-Control",	0,0,	TRUE },
	{ HTTP_FIELD_CONNECTION,		"Connection",		0,0,	TRUE },
	{ HTTP_FIELD_DATE,			"Date",			0,0,	TRUE },
	{ HTTP_FIELD_PRAGMA,			"Pragma",		0,0,	TRUE },
	{ HTTP_FIELD_TRANSFER_ENCONDING,	"Transfer-Encoding",	0,0,	TRUE },
	{ HTTP_FIELD_UPGRADE,			"Upgrade",		0,0,	TRUE },
	{ HTTP_FIELD_VIA,			"Via",			0,0,	TRUE },
	{ HTTP_FIELD_ACCEPT,			"Accept",		0,0,	TRUE },
	{ HTTP_FIELD_ACCEPT_CHARSET,		"Accept-Charset",	0,0,	TRUE },
	{ HTTP_FIELD_ACCEPT_ENCODING,		"Accept-Encoding",	0,0,	TRUE },
	{ HTTP_FIELD_ACCEPT_LANGUAGE,		"Accept-Language",	0,0,	TRUE },
	{ HTTP_FIELD_ACCEPT_RANGES,		"Accept-Ranges",	0,0,	TRUE },
	{ HTTP_FIELD_AUTHORIZATION,		"Authorization",	0,0,	TRUE },
	{ HTTP_FIELD_FROM,			"From",			0,0,	TRUE },
	{ HTTP_FIELD_AGE,			"Age",			0,0,	TRUE },
	{ HTTP_FIELD_HOST,			"Host",			0,0,	TRUE },
	{ HTTP_FIELD_IF_MODIFIED_SINCE,		"If-Modified-Since",	0,0,	TRUE },
	{ HTTP_FIELD_IF_MATCH,			"If-Match",		0,0,	TRUE },
	{ HTTP_FIELD_IF_NONE_MATCH,		"If-None-Match",	0,0,	TRUE },
	{ HTTP_FIELD_IF_RANGE,			"If-Range",		0,0,	TRUE },
	{ HTTP_FIELD_IF_UNMODIFIED_SINCE,	"If-Unmodified-Since",	0,0,	TRUE },
	{ HTTP_FIELD_MAX_FORWARDS,		"Max-Forwards",		0,0,	TRUE },
	{ HTTP_FIELD_PROXY_AUTHORIZATION,	"Proxy-Authorization",	0,0,	TRUE },
	{ HTTP_FIELD_PROXY_AUTENTICATE,		"Proxy-Autenticate",	0,0,	TRUE },
	{ HTTP_FIELD_RANGE,			"Range",		0,0,	TRUE },
	{ HTTP_FIELD_REFERER,			"Referer",		0,0,	TRUE },
	{ HTTP_FIELD_RETRY_AFTER,		"Retry-After",		0,0,	TRUE },
	{ HTTP_FIELD_USER_AGENT,		"User-Agent",		0,0,	TRUE },
	{ HTTP_FIELD_SERVER,			"Server",		0,0,	TRUE },
	{ HTTP_FIELD_ALLOW,			"Allow",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_BASE,		"Content-Base",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_ENCODING,		"Content-Encoding",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LANGUAGE,		"Content-Language",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LENGTH,		"Content-Length",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LOCATION,		"Content-Location",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_MD5,		"Content-MD5",		0,0,	FALSE },
	{ HTTP_FIELD_CONTENT_RANGE,		"Content-Range",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_TYPE,		"Content-Type",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_ETAG,		"Etag",			0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_EXPIRES,		"Expires",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LAST_MODIFIED,	"Last-Modified",	0,0,	TRUE },
	{ HTTP_FIELD_COOKIE,			"Cookie",		0,0,	FALSE },
	{ HTTP_FIELD_COOKIE2,			"Cookie2",		0,0,	FALSE },
	{ HTTP_FIELD_UA_CPU,			"UA-CPU",		0,0,	TRUE },
	{ HTTP_FIELD_UA_OS,			"UA-OS",		0,0,	TRUE },
	{ HTTP_FIELD_X_FORWARDED_FOR,		"X-Forwarded-For",	0,0,	TRUE },
	{ HTTP_FIELD_KEEP_ALIVE,		"Keep-Alive",		0,0,	TRUE },
	{ HTTP_FIELD_CLIENT_IP,			"Client-ip",		0,0,	TRUE },
	{ HTTP_FIELD_X_FLASH_VERSION,		"x-flash-version",	0,0,	TRUE },
	{ HTTP_FIELD_UNLESS_MODIFIED_SINCE,	"Unless-Modified-Since",0,0,	TRUE },
	{ HTTP_FIELD_TE,			"TE",			0,0,	TRUE },
	{ HTTP_FIELD_WEFERER,			"Weferer",		0,0,	TRUE }, /* mirar en internet es un campo raro */
	{ HTTP_FIELD_EXPECT,			"Expect",		0,0,	TRUE }, 
	{ HTTP_FIELD_CONTENT_DISPOSITION,	"Content-Disposition",	0,0,	TRUE }, 
	{ HTTP_FIELD_X_MOZ,			"X-Moz",		0,0,	TRUE }, 
	{ HTTP_FIELD_X_ICAP_VERSION,		"X-ICAP-Version",	0,0,	TRUE }, 
	{ HTTP_FIELD_NPFREFR,			"NpfRefr",		0,0,	TRUE }, 
	{ HTTP_FIELD_X_VERMEER_CONTENT_TYPE,	"X-Vermeer-Content-Type",0,0,	TRUE },
	{ HTTP_FIELD_MIME_VERSION,		"MIME-Version",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_TYPE_1,		"Content-type",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_TYPE_2,		"content-type",		0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LENGTH_1,		"Content-length",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_LENGTH_2,		"content-length",	0,0,	TRUE },
	{ HTTP_FIELD_USER_AGENT_1,		"User-agent",		0,0,	TRUE },
	{ HTTP_FIELD_USER_AGENT_2,		"user-agent",		0,0,	TRUE },
	{ HTTP_FIELD_PROXY_CONNECTION,		"Proxy-Connection",	0,0,	TRUE },
	{ HTTP_FIELD_CONTENT_FILTER_HELPER,	"Content-Filter-Helper",0,0,	TRUE },
	{ HTTP_FIELD_UNKNOWN,			"Unknown parameter",	0,0,	TRUE },
	{}
};

static int HT_GetHeaderMethod(char *data) {
	register int i;

	for (i = HTTP_HEADER_GET;i< HTTP_HEADER_UNKNOWN;i++)
        	if(strncmp(ST_HTTPTypeHeaders[i].name,data,strlen(ST_HTTPTypeHeaders[i].name)) == 0) 
                	return i;
	return HTTP_HEADER_UNKNOWN;
}

#endif
