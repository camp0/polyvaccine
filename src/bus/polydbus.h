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

#ifndef _POLYDBUS_H_
#define _POLYDBUS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <sys/poll.h>
#include "callbacks.h"

#define MAX_WATCHES 4

#define MAX_DBUS_SEGMENT_BUFFER 2048

struct ST_PolyDbus{
	DBusWatch *watches[MAX_WATCHES];
	struct pollfd pollfds[MAX_WATCHES];
	int total_watches;
	GHashTable *public_callbacks;
	GHashTable *private_callbacks;
	GList *interfaces;
};
typedef struct ST_PolyDbus ST_PolyDbus;

void PODS_Init(void);
void PODS_Destroy(void);
void PODS_AddInterface(ST_Interface *iface);
void PODS_AddPublicCallback(ST_Callback *call);
void PODS_AddPrivateCallback(ST_Callback *call);
DBusConnection *PODS_Connect(char *interface,void *engine);
int PODS_GetTotalActiveDescriptors(void);
int PODS_GetDescriptorByIndex(int i);
DBusWatch *PODS_GetWatchByIndex(int i);
int PODS_GetEventsByIndex(int i);
void PODS_Handler(DBusConnection *conn,short events, DBusWatch *watch);
void PODS_SendSuspiciousSegment(DBusConnection *conn,char *objectname,char *interfacename,char *name,unsigned char *ptr,int length);
void PODS_SendVerifiedSegment(DBusConnection *conn,char *objectname,char *interfacename, char *name,int32_t seq,unsigned long hash, int veredict);

#endif
