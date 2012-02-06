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
#include "debug.h"
#include "cache.h"
#include "genericflow.h"

struct ST_GenericAnalyzer{
	int16_t port;
	char name[32];
	void (*init)();
	void (*destroy)();
	void (*stats)();
	void (*analyze)(ST_Cache *c,ST_GenericFlow *f,int *ret);
	void (*learn)(ST_Cache *c,ST_GenericFlow *f);
};
typedef struct ST_GenericAnalyzer ST_GenericAnalyzer;

struct ST_Forwarder {
	GHashTable *analyzers;
};
typedef struct ST_Forwarder ST_Forwarder;

ST_Forwarder *FORD_Init(void);
void FORD_Destroy(ST_Forwarder *fw);
void FORD_InitAnalyzers(ST_Forwarder *fw);
void FORD_Stats(ST_Forwarder *fw);
ST_GenericAnalyzer *FORD_GetAnalyzer(ST_Forwarder *fw,int16_t port);

void FORD_AddAnalyzer(ST_Forwarder *fw,char *name,int16_t port,void (*init)(), 
	void (*destroy)(),void (*stats)(),
	void (*analyze)(ST_Cache *c,ST_GenericFlow *f,int *ret),
	void (*learn)(ST_Cache *c,ST_GenericFlow *f));

#endif
