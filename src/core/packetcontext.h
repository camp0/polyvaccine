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

#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800

struct ST_PacketContext {
	struct iphdr *ip;
	struct tcphdr *tcp;
	unsigned char *payload;
	int len;
	struct timeval *now;
};

typedef struct ST_PacketContext ST_PacketContext;

ST_PacketContext _pktctx;
//static ST_PacketContext _pktctx;
	
static void PKCX_Init(void) { _pktctx.ip= NULL;_pktctx.tcp = NULL;_pktctx.payload = NULL;_pktctx.len=0;};
static void PKCX_Destroy(void) { return;};
static void PKCX_SetIPHeader(const unsigned char* packet) { _pktctx.ip = (struct iphdr*)packet;} ;
static void PKCX_SetTCPHeader(const unsigned char *packet) { _pktctx.tcp = (struct tcphdr*)packet; };
static void PKCX_SetL7Payload(const unsigned char *packet,int length) {_pktctx.payload = packet;_pktctx.len = length;};

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

/*
bool isFragment() const { return (ntohs(_ip->frag_off) & 0x3fff); }
u_int16_t getID() const { return ntohs(_ip->id); }
int getVersion() const { return _ip->version; }
int getIPProtocol() const { return _ip->protocol; }
u_int32_t getIPSrcAddr() const { return _ip->saddr; }
u_int32_t getIPDstAddr() const { return _ip->daddr; }
const char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=_ip->saddr; return inet_ntoa(a); }
const char* getDstAddrDotNotation() const { in_addr a; a.s_addr=_ip->daddr; return inet_ntoa(a); }
u_int32_t getIPPayloadLength() const { return getIPPacketLength() - getIPHeaderLength(); }

u_int16_t getTCPSrcPort() const { return ntohs(_tcp->source); }
u_int16_t getTCPDstPort() const { return ntohs(_tcp->dest); }
u_int32_t getTCPSequence() const  { return ntohl(_tcp->seq); }
u_int32_t getTCPAckSequence() const  { return ntohl(_tcp->ack_seq); }
u_int16_t getTCPWindow() const { return _tcp->window; }
bool isTCPSyn() const { return _tcp->syn; }
bool isTCPFin() const { return _tcp->fin; }
bool isTCPAck() const { return _tcp->ack; }
bool isTCPRst() const { return _tcp->rst; }
bool isTCPPushSet() const { return _tcp->psh; }
unsigned int getTCPSegmentLength() const { return ntohs(_ip->tot_len) - _ip->ihl * 4; }
unsigned int getTCPPayloadLength() const { return ntohs(_ip->tot_len) - _ip->ihl * 4 - _tcp->doff * 4; }
unsigned int getTCPHeaderLength() const { return _tcp->doff * 4; }

u_int16_t PKCX_GetPayloadLength() const { return _payloadLength;}
unsigned char* PKCX_GetPayload() const { return _payload; }
u_int16_t getSrcPort() const { return _srcport; }
u_int16_t getDstPort() const { return _dstport; }
struct timeval *getTimeStamp() { return &_now; }
void setTimeStamp(struct timeval *now) { _now.tv_sec = now->tv_sec; _now.tv_usec = now->tv_usec;}
*/
#endif
