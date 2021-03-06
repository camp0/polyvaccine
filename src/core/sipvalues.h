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

#ifndef _SIPVALUES_H_
#define _SIPVALUES_H_

#define CRLF "\r\n"

struct ST_SIPField {
	int nfield;
	char *name;
	int32_t matchs;
	int have_data;
	int check_cache;
};
typedef struct ST_SIPField ST_SIPField;

enum {
	/* Header types */
	SIP_HEADER_REGISTER  = 0,
	SIP_HEADER_INVITE,
	SIP_HEADER_ACK,
	SIP_HEADER_CANCEL,
	SIP_HEADER_BYE,
	SIP_HEADER_OPTIONS,
	SIP_HEADER_MESSAGE,
	SIP_HEADER_UNKNOWN
};

static ST_SIPField ST_SIPTypeHeaders[] = {
	{	
		.nfield 	=	SIP_HEADER_REGISTER,
		.name 		= 	"REGISTER",
		.matchs		=	0,
		.have_data	=	0,
		.check_cache	=	0
	},
	{
		.nfield		=	SIP_HEADER_INVITE,
		.name		=	"INVITE",
		.matchs		=	0,
		.have_data	=	TRUE, // the invite messages usually contains the sdp descriptor.
		.check_cache	=	0
	},
	{
		.nfield		=	SIP_HEADER_ACK,
		.name		=	"ACK",
		.matchs		=	0,
		.have_data	=	0,
		.check_cache	=	0,
	},
        {
                .nfield         =	SIP_HEADER_CANCEL,
                .name           =	"CANCEL",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       0,
        },
        {
                .nfield         =	SIP_HEADER_BYE,
                .name           =	"BYE",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       0,
        },
        {
                .nfield         =	SIP_HEADER_OPTIONS,
                .name           =	"OPTIONS",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       0,
        },
        {
                .nfield         =       SIP_HEADER_MESSAGE,
                .name           =       "MESSAGE",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       0,
        },
        {
                .nfield         =       SIP_HEADER_UNKNOWN,
                .name           =       "UNKNOWN",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       0,
        },
	{}
};

enum {
	/* Header Fields */
	SIP_FIELD_ACCEPT = 0,
	SIP_FIELD_ACCEPT_ENCODING,
	SIP_FIELD_ACCEPT_LANGUAGE,
	SIP_FIELD_ALERT_INFO,
	SIP_FIELD_ALLOW,
	SIP_FIELD_AUTHENTICATION_INFO,
	SIP_FIELD_AUTHORIZATION,
	SIP_FIELD_CALL_ID,
	SIP_FIELD_CALL_INFO,
	SIP_FIELD_CONTACT,
	SIP_FIELD_CONTENT_DISPOSITION,
	SIP_FIELD_CONTENT_ENCODING,
	SIP_FIELD_CONTENT_LANGUAGE,
	SIP_FIELD_CONTENT_LENGTH,
	SIP_FIELD_CONTENT_TYPE,
	SIP_FIELD_CSEQ,
	SIP_FIELD_DATE,
	SIP_FIELD_ERROR_INFO,
	SIP_FIELD_EXPIRES,
	SIP_FIELD_FROM,
	SIP_FIELD_IN_REPLY_TO,
	SIP_FIELD_MAX_FORWARDS,
	SIP_FIELD_MIN_EXPIRES,
	SIP_FIELD_MIME_VERSION,
	SIP_FIELD_ORGANIZATION,
	SIP_FIELD_PRIORITY,
	SIP_FIELD_PROXY_AUTHENTICATE,
	SIP_FIELD_PROXY_AUTHORIZATION,
	SIP_FIELD_PROXY_REQUIRE,
	SIP_FIELD_RECORD_ROUTE,
	SIP_FIELD_REPLY_TO,
	SIP_FIELD_REQUIRE,
	SIP_FIELD_RETRY_AFTER,
	SIP_FIELD_ROUTE,
	SIP_FIELD_SERVER,
	SIP_FIELD_SUBJECT,
	SIP_FIELD_SUPPORTED,
	SIP_FIELD_TIMESTAMP,
	SIP_FIELD_TO,
	SIP_FIELD_UNSUPPORTED,
	SIP_FIELD_USER_AGENT,
	SIP_FIELD_VIA,
	SIP_FIELD_WARNING,
	SIP_FIELD_WWW_AUTHENTICATE,
	/* Request headers */
	/* Response headers */
	/* Other headers */

	SIP_FIELD_UNKNOWN // just for counting pourposes
};

static ST_SIPField ST_SIPFields [] = {
	{
                .nfield         =       SIP_FIELD_ACCEPT,
                .name           =       "Accept",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =      	TRUE,
	},
        {
                .nfield         =       SIP_FIELD_ACCEPT_ENCODING,
                .name           =       "Accept-Encoding",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_ACCEPT_LANGUAGE,
                .name           =       "Accept-Language",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_ALERT_INFO,
                .name           =       "Alert-Info",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_ALLOW,
                .name           =       "Allow",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_AUTHENTICATION_INFO,
                .name           =       "Authentication-Info",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_AUTHORIZATION, 
                .name           =       "Authorization",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_CALL_ID,
                .name           =       "Call-ID",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_CALL_INFO, 
                .name           =       "Call-Info",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_CONTACT, 
                .name           =       "Contact",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_CONTENT_DISPOSITION, 
                .name           =       "Content-Disposition",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_CONTENT_ENCODING,
                .name           =       "Content-Enconding",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_CONTENT_LANGUAGE, 
                .name           =       "Content-Language",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_CONTENT_LENGTH, 
                .name           =       "Content-Length",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_CONTENT_TYPE,
                .name           =       "Content-Type",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_CSEQ,
                .name           =       "CSeq",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_DATE, 
                .name           =       "Date",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_ERROR_INFO,
                .name           =       "Error-Info",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_EXPIRES,
                .name           =       "Expires",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_FROM,
                .name           =       "From",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_IN_REPLY_TO, 
                .name           =       "In-Reply-To",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_MAX_FORWARDS, 
                .name           =       "Max-Forwards",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_MIN_EXPIRES,
                .name           =       "Min-Expires",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_MIME_VERSION,
                .name           =       "MIME-Version",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_ORGANIZATION,
                .name           =    	"Organization",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_PRIORITY,
                .name           =       "Priority",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_PROXY_AUTHENTICATE,
                .name           =       "Proxy-Authenticate",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_PROXY_AUTHORIZATION,
                .name           =       "Proxy-Authorization",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_PROXY_REQUIRE,
                .name           =       "Proxy-Require",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_RECORD_ROUTE, 
                .name           =       "Record-Route",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =     	SIP_FIELD_REPLY_TO, 
                .name           =       "Reply-To",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =     	SIP_FIELD_REQUIRE, 
                .name           =       "Require",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =      	SIP_FIELD_RETRY_AFTER, 
                .name           =       "Retry-After",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =     	SIP_FIELD_ROUTE, 
                .name           =       "Route",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_SERVER,
                .name           =       "Server",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_SUBJECT,
                .name           =       "Subject",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_SUPPORTED,
                .name           =       "Supported",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_TIMESTAMP,
                .name           =       "Timestamp",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_TO,
                .name           =       "To",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_UNSUPPORTED,
                .name           =       "Unsupported",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_USER_AGENT,
                .name           =       "User-Agent",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_VIA,
                .name           =       "Via",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_WARNING,
                .name           =       "Warning",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
        {
                .nfield         =       SIP_FIELD_WWW_AUTHENTICATE,
                .name           =       "WWW-Authenticate",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
	/* Last sip field */
        {
                .nfield         =       SIP_FIELD_UNKNOWN,
                .name           =       "Unknown parameter",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =       TRUE,
        },
	{}
};

/*
int HT_GetHeaderMethod(char *data) {
	register int i;

	for (i = SIP_HEADER_REGISTER;i< SIP_HEADER_UNKNOWN;i++)
        	if(strncmp(ST_HttpTypeHeaders[i].name,data,strlen(ST_HttpTypeHeaders[i].name)) == 0) 
                	return i;
	return SIP_HEADER_UNKNOWN;
}
*/
#endif
