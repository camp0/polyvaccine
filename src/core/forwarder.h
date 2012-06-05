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

#ifndef _FORWARDER_H_
#define _FORWARDER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include <log4c.h>
#include "debug.h"
#include "cache.h"
#include "user.h"
#include "genericflow.h"
#include "interfaces.h"
#include "polydbus.h"

struct ST_GenericAnalyzer{
	int16_t port;
	int16_t protocol;
	short direction;
	char name[32];
	void (*init)(void);
	void (*destroy)(void);
	void (*stats)(FILE *out);
	void (*analyze)(ST_User *user,ST_GenericFlow *f,int *ret);
	void (*learn)(ST_User *user,ST_GenericFlow *f);
	void (*notify_correct)(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq);
	void (*notify_wrong)(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq);
};
typedef struct ST_GenericAnalyzer ST_GenericAnalyzer;

struct ST_Forwarder {
	GHashTable *tcp_analyzers; // active tcp analyzers
	GHashTable *udp_analyzers; // active udp analyzers
	GHashTable *analyzers; // All the analyzers available
};
typedef struct ST_Forwarder ST_Forwarder;

ST_Forwarder *FORD_Init(void);
void FORD_Destroy(ST_Forwarder *fw);
void FORD_InitAnalyzers(ST_Forwarder *fw);
void FORD_ShowAnalyzers(ST_Forwarder *fw);
void FORD_Stats(ST_Forwarder *fw,FILE *out);
ST_GenericAnalyzer *FORD_GetAnalyzer(ST_Forwarder *fw,int16_t protocol,int16_t sport,int16_t dport);
ST_GenericAnalyzer *FORD_GetAnalyzerByName(ST_Forwarder *fw,char *name);

void FORD_AddAnalyzer(ST_Forwarder *fw,char *name,int16_t protocol, int16_t port,
	void (*init)(void), 
	void (*destroy)(void),
	void (*stats)(FILE *out),
	void (*analyze)(ST_User *user,ST_GenericFlow *f,int *ret),
	void (*learn)(ST_User *user,ST_GenericFlow *f),
	void (*notify_correct)(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq),
	void (*notify_wrong)(DBusConnection *bus,ST_User *user,ST_GenericFlow *f,unsigned long hash,u_int32_t seq)
);

void FORD_ChangeAnalyzerToPlugOnPort(ST_Forwarder *fw,int16_t src_protocol, int16_t src_port,
	int16_t dst_protocol,int16_t dst_port);

void FORD_AddPortToAnalyzer(ST_Forwarder *fw,char *name,int16_t protocol,int16_t port);
void FORD_ChangePortToAnalyzer(ST_Forwarder *fw,char *name,int16_t port);

void FORD_EnableAnalyzerByName(ST_Forwarder *fw, char *name);

#endif
