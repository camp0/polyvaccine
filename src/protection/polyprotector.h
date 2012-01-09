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
#ifndef _POLYPROTECTOR_H_
#define _POLYPROTECTOR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "stdio.h"
#include "debug.h"
#include "polydbus.h"
#include "callbacks.h" 
#include <glib.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include "../core/system.h"
#include "nfpacketpool.h"
#include <linux/if_ether.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include "../core/authorized.h"
#include "banner.h"

#define POLYVACCINE_PROTECTOR_INTERFACE "polyvaccine.protector"
#define POLYVACCINE_PROTECTION_ENGINE_NAME "Polyvaccine protection engine"

struct ST_PolyProtector {
        DBusConnection *bus;
	GHashTable *table; // connection table 
	ST_NfFlowPool *pool;
	/** The main Handler of netfilter Queue */
	struct nfq_q_handle *qh;
	/** The main Handler of netfilter */
	struct nfq_handle *h;
	ST_AuthorizedHost *hosts;

	int dev_index;

	/** stats */
	uint64_t total_tcp_segments;
	uint64_t total_tcp_packets;
	uint64_t total_inbound_packets;
	uint64_t tcp_retransmition_drop_segments;
	uint64_t tcp_drop_segments;
};

typedef struct ST_PolyProtector ST_PolyProtector;

#define MAX_PUBLIC_INTERFACES 1

void PRCA_Signaling_AuthorizeSegment(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_SIGNAL_CALLBACKS 1 
static ST_Callback ST_StaticSignalCallbacks[ MAX_SIGNAL_CALLBACKS] = {
	{ "veredict",		"a",NULL,	PRCA_Signaling_AuthorizeSegment }
};

void PRCA_Property_GetTotalInboundPackets(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalTcpPackets(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalTcpSegments(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTcpRetransmitionDropSegments(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTcpDropSegments(DBusConnection *conn,DBusMessage *msg, void *data);

#define MAX_PROPERTY_CALLBACKS 5 
static ST_Callback ST_StaticPropertyCallbacks[MAX_PROPERTY_CALLBACKS] = {
	{ "inbound packets",	NULL,"x",	PRCA_Property_GetTotalInboundPackets },
	{ "tcp packets",	NULL,"x",	PRCA_Property_GetTotalTcpPackets },
	{ "tcp segments",	NULL,"x",	PRCA_Property_GetTotalTcpSegments },
	{ "retransmition drop tcp segments",	NULL,"x",	PRCA_Property_GetTcpRetransmitionDropSegments },
	{ "drop tcp segments",	NULL,"x",	PRCA_Property_GetTcpDropSegments }
};

static ST_Interface ST_PublicInterfaces [MAX_PUBLIC_INTERFACES] = {
        { POLYVACCINE_PROTECTOR_INTERFACE,
		0,MAX_SIGNAL_CALLBACKS,MAX_PROPERTY_CALLBACKS,
                NULL,ST_StaticSignalCallbacks,ST_StaticPropertyCallbacks 
        }
};

void POPR_Init(void);
void POPR_Run(void);
void POPR_SetDevice(char *dev);
void POPR_Exit(void);
void POPR_AddAuthorizedHost(char *ip);

#endif
