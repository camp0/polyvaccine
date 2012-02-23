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

#ifndef _TCPANALYZER_H_
#define _TCPANALYZER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/tcp.h>
#include "packetcontext.h"
#include "genericflow.h"
#include <sys/types.h>
#include <glib.h>
#include "debug.h"
#include "interfaces.h"

struct ST_TCPAnalyzer{
	/* statistics */
	int32_t total_syn;
	int32_t total_synack;
	int32_t total_ack;
	int32_t total_rst;
	int32_t total_fin;
	int32_t total_bad_flags;

	int64_t total_tcp_bytes;
	int64_t total_tcp_segments;
};

typedef struct ST_TCPAnalyzer ST_TCPAnalyzer;

#define POLY_TCPS_OK            (-1)
#define POLY_TCPS_CLOSED        0
#define POLY_TCPS_SYN_SENT      1
#define POLY_TCPS_SIMSYN_SENT   2
#define POLY_TCPS_SYN_RECEIVED  3
#define POLY_TCPS_ESTABLISHED   4
#define POLY_TCPS_FIN_SEEN      5
#define POLY_TCPS_CLOSE_WAIT    6
#define POLY_TCPS_FIN_WAIT      7
#define POLY_TCPS_CLOSING       8
#define POLY_TCPS_LAST_ACK      9
#define POLY_TCPS_TIME_WAIT     10
#define POLY_TCP_NSTATES        11

void TCAZ_Init(void);
void TCAZ_Destroy(void);
void TCAZ_Analyze(ST_GenericFlow *f);
void TCAZ_Stats(void);

#endif
