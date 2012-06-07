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

#ifndef _PACKETDECODER_H_
#define _PACKETDECODER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <pcap.h>
#include <sys/time.h>
#include <stdio.h>
#ifdef __LINUX__
#include <linux/if_ether.h>
#endif
#ifdef __FREEBSD__
#include <net/ethernet.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include "debug.h"

#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800

struct ST_PacketDecoder {
        int64_t _totalEthernetPackets;
        int64_t _totalEthernetVlanPackets;
        int64_t _totalIpPackets;
        int64_t _totalIpv6Packets;
        int64_t _totalTcpPackets;
        int64_t _totalUdpPackets;
        int64_t _totalUnknownPackets;
	int64_t _totalL7Packets;
};

typedef struct ST_PacketDecoder ST_PacketDecoder;

void PKDE_Init(void);
void PKDE_Destroy(void);
void PKDE_Stats(FILE *output);
int PKDE_Decode(struct pcap_pkthdr *hdr, unsigned char *packet);

#endif

