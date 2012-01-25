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

struct ST_SipField {
	int nfield;
	char *name;
	int32_t matchs;
	int have_data;
	int check_cache;
};
typedef struct ST_SipField ST_SipField;

enum {
	/* Header types */
	SIP_HEADER_REGISTER  = 0,
	SIP_HEADER_INVITE,
	SIP_HEADER_ACK,
	SIP_HEADER_CANCEL,
	SIP_HEADER_BYE,
	SIP_HEADER_OPTIONS,
	SIP_HEADER_UNKNOWN
};

static ST_SipField ST_SipTypeHeaders[] = {
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
	SIP_FIELD_ORGANIZATION,
	/* Request headers */
	/* Response headers */
	/* Other headers */

	SIP_FIELD_UNKNOWN // just for counting pourposes
};

static ST_HttpField ST_HttpFields [] = {
	{
                .nfield         =       SIP_FIELD_ACCEPT,
                .name           =       "Accept",
                .matchs         =       0,
                .have_data      =       0,
                .check_cache    =      	TRUE,
	},
	{}
};

int HT_GetHeaderMethod(char *data) {
	register int i;

	for (i = SIP_HEADER_GET;i< SIP_MAX_HEADER;i++)
        	if(strncmp(ST_HttpTypeHeaders[i].name,data,strlen(ST_HttpTypeHeaders[i].name)) == 0) 
                	return i;
	return SIP_HEADER_UNKNOWN;
}

#endif
