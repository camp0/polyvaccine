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

#ifndef _PACKETCONTEXT_H_
#define _PACKETCONTEXT_H_

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800

struct ST_PacketContext {
#ifdef __LINUX__
	struct iphdr *ip;
#endif
#ifdef __FREEBSD__
	struct ip *ip;
#endif
	struct tcphdr *tcp;
	unsigned char *payload;
	int len;
	struct timeval *now;
};

typedef struct ST_PacketContext ST_PacketContext;

ST_PacketContext _pktctx;
	
static void PKCX_Init(void) { _pktctx.ip= NULL;_pktctx.tcp = NULL;_pktctx.payload = NULL;_pktctx.len=0;};
static void PKCX_Destroy(void) { return;};
static void PKCX_SetTCPHeader(const unsigned char *packet) { _pktctx.tcp = (struct tcphdr*)packet; };
static void PKCX_SetL7Payload(const unsigned char *packet,int length) {_pktctx.payload = packet;_pktctx.len = length;};

#ifdef __LINUX__

static void PKCX_SetIPHeader(const unsigned char* packet) { _pktctx.ip = (struct iphdr*)packet;} ;

/* IP Fields */
static void PKCX_SetIPSrcAddr(u_int32_t saddr) { _pktctx.ip->saddr = saddr; }
static void PKCX_SetIPDstAddr(u_int32_t daddr) { _pktctx.ip->daddr = daddr; }
static u_int32_t PKCX_GetIPSrcAddr(void) { return _pktctx.ip->saddr; }
static u_int32_t PKCX_GetIPDstAddr(void) { return _pktctx.ip->daddr; }
static u_int8_t PKCX_GetTTL(void) { return _pktctx.ip->ttl; }
static u_int32_t PKCX_GetIPPacketLength(void) { return ntohs(_pktctx.ip->tot_len); }
static u_int16_t PKCX_GetIPHeaderLength(void) { return _pktctx.ip->ihl * 4; }
static int PKCX_IsIPver4(void) { return _pktctx.ip->version == 4; }
static int PKCX_GetIPProtocol(void) { return _pktctx.ip->protocol; }
/* TCP Fields */
static unsigned int PKCX_GetTCPPayloadLength(void) { return ntohs(_pktctx.ip->tot_len) - _pktctx.ip->ihl * 4 - _pktctx.tcp->doff * 4; }
static int PKCX_GetPayloadLength(void) { return _pktctx.len; }
static unsigned int PKCX_GetTCPHeaderLength(void) { return _pktctx.tcp->doff * 4; }
static u_int16_t PKCX_GetTCPSrcPort(void) { return ntohs(_pktctx.tcp->source); }
static u_int16_t PKCX_GetTCPDstPort(void) { return ntohs(_pktctx.tcp->dest); }
static int PKCX_IsTCPPush(void) { return _pktctx.tcp->psh; }
static unsigned char *PKCX_GetPayload(void) { return _pktctx.payload;}
static char* PKCX_GetSrcAddrDotNotation(void) { struct in_addr a; a.s_addr=_pktctx.ip->saddr; return inet_ntoa(a); }
static char* PKCX_GetDstAddrDotNotation(void) { struct in_addr a; a.s_addr=_pktctx.ip->daddr; return inet_ntoa(a); }
static u_int32_t PKCX_GetTCPSequenceNumber(void) { return ntohl(_pktctx.tcp->seq); }

#endif // LINUX

#ifdef __FREEBSD__

static void PKCX_SetIPHeader(const unsigned char* packet) { _pktctx.ip = (struct ip*)packet;} ;

static void PKCX_SetIPSrcAddr(u_int32_t saddr) { _pktctx.ip->ip_src.s_addr = saddr; }
static void PKCX_SetIPDstAddr(u_int32_t daddr) { _pktctx.ip->ip_dst.s_addr = daddr; }
static u_int32_t PKCX_GetIPSrcAddr(void) { return _pktctx.ip->ip_src.s_addr; }
static u_int32_t PKCX_GetIPDstAddr(void) { return _pktctx.ip->ip_dst.s_addr; }
static u_int8_t PKCX_GetTTL(void) { return _pktctx.ip->ip_ttl; }
static u_int32_t PKCX_GetIPPacketLength(void) { return ntohs(_pktctx.ip->ip_len); }
static u_int16_t PKCX_GetIPHeaderLength(void) { return _pktctx.ip->ip_hl * 4; }
static int PKCX_IsIPver4(void) { return _pktctx.ip->ip_v == 4; }
static int PKCX_GetIPProtocol(void) { return _pktctx.ip->ip_p; }

static unsigned int PKCX_GetTCPPayloadLength(void) { return ntohs(_pktctx.ip->ip_len) - _pktctx.ip->ip_hl * 4 - _pktctx.tcp->th_off * 4; }
static int PKCX_GetPayloadLength(void) { return _pktctx.len; }
static unsigned int PKCX_GetTCPHeaderLength(void) { return _pktctx.tcp->th_off * 4; }
static u_int16_t PKCX_GetTCPSrcPort(void) { return ntohs(_pktctx.tcp->th_sport); }
static u_int16_t PKCX_GetTCPDstPort(void) { return ntohs(_pktctx.tcp->th_dport); }
static int PKCX_IsTCPPush(void) { 
	if(_pktctx.tcp->th_flags & TH_PUSH)
		return 1;
	else
		return 0;
 }
static unsigned char *PKCX_GetPayload(void) { return _pktctx.payload;}

static char* PKCX_GetSrcAddrDotNotation(void) { 
	static char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(_pktctx.ip->ip_src), ip, INET_ADDRSTRLEN);
	return &ip;
}
static char* PKCX_GetDstAddrDotNotation(void) { 
	static char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(_pktctx.ip->ip_dst), ip, INET_ADDRSTRLEN);
	return &ip;
}
static u_int32_t PKCX_GetTCPSequenceNumber(void) { return ntohl(_pktctx.tcp->th_seq); }

#endif // FREEBSD


#endif
