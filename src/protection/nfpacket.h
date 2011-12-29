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
#ifndef _NFPACKET_H_
#define _NFPACKET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "stdio.h"
#include "debug.h"
#include <glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "polyprotector.h"
#include "flow.h"
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_PKT_BUFFER_SIZE 2048

void NFPK_SetFlowResolution(ST_PolyProtector *popr,ST_Flow *f, int resolution);
void NFPK_CloseNfq(ST_PolyProtector *popr);
int NFPK_InitNfq(ST_PolyProtector *popr);
ST_Flow *NFPK_GetFlowByHash(GHashTable *t,unsigned long hash1,unsigned long hash2);
#endif
