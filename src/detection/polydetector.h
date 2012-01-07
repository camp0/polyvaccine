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

#include <stdio.h>
#include "debug.h"
#include "banner.h"
#include "polydbus.h"
#include "callbacks.h" 
#include "context.h"
#include <glib.h>
#include <dbus/dbus.h>

enum {
        POLYDETECTOR_STATE_STOP = 0,
        POLYDETECTOR_STATE_RUNNING
} polydetector_states;

static const char *polydetector_states_str [] = { "stop","running"};

#define POLYVACCINE_DETECTION_INTERFACE "polyvaccine.detector"
#define POLYVACCINE_DETECTION_ENGINE_NAME "Detection engine"

struct ST_PolyDetector {
        DBusConnection *bus;
	int state;
	int32_t executed_segments;
	int32_t shellcodes_detected;
	unsigned char buffer[MAX_DBUS_SEGMENT_BUFFER];
};

typedef struct ST_PolyDetector ST_PolyDetector;

#define MAX_PUBLIC_INTERFACES 1

void PRCA_Signaling_AnalyzeSegment(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_SIGNAL_CALLBACKS 1
static ST_Callback ST_StaticSignalCallbacks[ MAX_SIGNAL_CALLBACKS] = {
	{ "Analyze",		"a",NULL,	PRCA_Signaling_AnalyzeSegment }
};

void PRCA_Property_GetNumberExecutedSegments(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetNumberShellcodesDetected(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_PROPERTY_CALLBACKS 2
static ST_Callback ST_StaticPropertyCallbacks[MAX_PROPERTY_CALLBACKS] = {
	{ "ExecutedSegments",	NULL,"i",	PRCA_Property_GetNumberExecutedSegments },
	{ "ShellcodesDetected",	NULL,"i",	PRCA_Property_GetNumberShellcodesDetected }
};

static ST_Interface ST_PublicInterfaces [MAX_PUBLIC_INTERFACES] = {
        { POLYVACCINE_DETECTION_INTERFACE,
                NULL,0,
                ST_StaticSignalCallbacks, MAX_SIGNAL_CALLBACKS,
                ST_StaticPropertyCallbacks,MAX_PROPERTY_CALLBACKS,
        }
};

void PODT_Init(void);
void PODT_Run(void);
void PODT_ShowAvailableSyscalls(void);
void PODT_ShowExecutionPath(int value);
void PODT_Destroy(void);

#endif
