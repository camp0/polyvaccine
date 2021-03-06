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
#ifndef _POLYDETECTOR_H_
#define _POLYDETECTOR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE 
#include <sched.h>
#include <stdio.h>
#include "debug.h"
#include "banner.h"
#include "polydbus.h"
#include "callbacks.h" 
#include "sandbox.h"
#include <glib.h>
#include <dbus/dbus.h>
#include "interfaces.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_DETECTION_INTERFACE
#include "log.h"

enum {
        POLYDETECTOR_STATE_STOP = 0,
        POLYDETECTOR_STATE_RUNNING
} polydetector_states;

static const char *polydetector_states_str [] = { "stop","running"};

#define POLYVACCINE_DETECTION_ENGINE_NAME "Polyvaccine detection engine"

struct ST_PolyDetector {
        DBusConnection *bus;
	char interface_name[1024];
	int state;
	ST_Sandbox *sandbox;	
	unsigned char buffer[MAX_DBUS_SEGMENT_BUFFER];
};

typedef struct ST_PolyDetector ST_PolyDetector;

void PRCA_Signaling_AnalyzeSegment(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticSignalCallbacks[] = {
	{ 
		.name	=	"Analyze",
		.in	=	"a",
		.out	=	NULL,
		.func	=	PRCA_Signaling_AnalyzeSegment 
	},
	{}
};

void PRCA_Property_GetNumberExecutedSegments(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberShellcodesDetected(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticPropertyCallbacks[] = {
	{ 
		.name	=	"ExecutedSegments",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetNumberExecutedSegments 
	},
	{ 
		.name	=	"ShellcodesDetected",
		.in	=	NULL,
		.out	=	"i",
		.func	=	PRCA_Property_GetNumberShellcodesDetected 
	},
	{}
};

static ST_Interface ST_PublicInterfaces [] = {
        { 
		.name		=	POLYVACCINE_DETECTION_INTERFACE,
		.methods	=	NULL,
		.signals	=	ST_StaticSignalCallbacks,
		.properties	=	ST_StaticPropertyCallbacks
	},
	{}
};

void PODT_Init(char *interface);
void PODT_SetCpu(int cpu);
void PODT_SetCourtesyTime(int seconds);
void PODT_SetShowExecutableSegment(int value);
void PODT_Run(void);
void PODT_Destroy(void);

#endif
