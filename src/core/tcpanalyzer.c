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

#include "tcpanalyzer.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_TCP_INTERFACE
#include "log.h"

static char *tcp_states [] = {
        "CLOSE",
        "SYN_SENT",
        "SIMSYN_SENT",
        "SYN_RECVEIVED",
	"ESTABLISHED",
        "FIN_SEEN",
        "CLOSE_WAIT",
        "FIN_WAIT",
        "CLOSING",
        "LAST_ACK",
        "TIMEWAIT"
};

/* tcp flags conversion */
#define	TCPFC_INVALID		0
#define	TCPFC_SYN		1
#define	TCPFC_SYNACK		2
#define	TCPFC_ACK		3
#define	TCPFC_FIN		4
#define	TCPFC_COUNT		5

/* TCP State table from BSD npf project */
static int tcp_finite_state_machine[POLY_TCP_NSTATES][2][TCPFC_COUNT] = {
	[POLY_TCPS_CLOSED] = {
		[FLOW_FORW] = {
			/* Handshake (1): initial SYN. */
			[TCPFC_SYN]	= POLY_TCPS_SYN_SENT,
		},
	},
	[POLY_TCPS_SYN_SENT] = {
		[FLOW_FORW] = {
			/* SYN may be retransmitted. */
			[TCPFC_SYN]	= POLY_TCPS_OK,
		},
		[FLOW_BACK] = {
			/* Handshake (2): SYN-ACK is expected. */
			[TCPFC_SYNACK]	= POLY_TCPS_SYN_RECEIVED,
			/* Simultaneous initiation - SYN. */
			[TCPFC_SYN]	= POLY_TCPS_SIMSYN_SENT,
		},
	},
	[POLY_TCPS_SIMSYN_SENT] = {
		[FLOW_FORW] = {
			/* Original SYN re-transmission. */
			[TCPFC_SYN]	= POLY_TCPS_OK,
			/* SYN-ACK response to simultaneous SYN. */
			[TCPFC_SYNACK]	= POLY_TCPS_SYN_RECEIVED,
		},
		[FLOW_BACK] = {
			/* Simultaneous SYN re-transmission.*/
			[TCPFC_SYN]	= POLY_TCPS_OK,
			/* SYN-ACK response to original SYN. */
			[TCPFC_SYNACK]	= POLY_TCPS_SYN_RECEIVED,
			/* FIN may be sent early. */
			[TCPFC_FIN]	= POLY_TCPS_FIN_SEEN,
		},
	},
	[POLY_TCPS_SYN_RECEIVED] = {
		[FLOW_FORW] = {
			/* Handshake (3): ACK is expected. */
			[TCPFC_ACK]	= POLY_TCPS_ESTABLISHED,
			/* FIN may be sent early. */
			[TCPFC_FIN]	= POLY_TCPS_FIN_SEEN,
		},
		[FLOW_BACK] = {
			/* SYN-ACK may be retransmitted. */
			[TCPFC_SYNACK]	= POLY_TCPS_OK,
			/* XXX: ACK of late SYN in simultaneous case? */
			[TCPFC_ACK]	= POLY_TCPS_OK,
			/* FIN may be sent early. */
			[TCPFC_FIN]	= POLY_TCPS_FIN_SEEN,
		},
	},
	[POLY_TCPS_ESTABLISHED] = {
		/*
		 * Regular ACKs (data exchange) or FIN.
		 * FIN packets may have ACK set.
		 */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			/* FIN by the sender. */
			[TCPFC_FIN]	= POLY_TCPS_FIN_SEEN,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			/* FIN by the receiver. */
			[TCPFC_FIN]	= POLY_TCPS_FIN_SEEN,
		},
	},
	[POLY_TCPS_FIN_SEEN] = {
		/*
		 * FIN was seen.  If ACK only, connection is half-closed now,
		 * need to determine which end is closed (sender or receiver).
		 * However, both FIN and FIN-ACK may race here - in which
		 * case we are closing immediately.
		 */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_CLOSE_WAIT,
			[TCPFC_FIN]	= POLY_TCPS_CLOSING,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_FIN_WAIT,
			[TCPFC_FIN]	= POLY_TCPS_CLOSING,
		},
	},
	[POLY_TCPS_CLOSE_WAIT] = {
		/* Sender has sent the FIN and closed its end. */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			[TCPFC_FIN]	= POLY_TCPS_LAST_ACK,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			[TCPFC_FIN]	= POLY_TCPS_LAST_ACK,
		},
	},
	[POLY_TCPS_FIN_WAIT] = {
		/* Receiver has closed its end. */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			[TCPFC_FIN]	= POLY_TCPS_LAST_ACK,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_OK,
			[TCPFC_FIN]	= POLY_TCPS_LAST_ACK,
		},
	},
	[POLY_TCPS_CLOSING] = {
		/* Race of FINs - expecting ACK. */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_LAST_ACK,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_LAST_ACK,
		},
	},
	[POLY_TCPS_LAST_ACK] = {
		/* FINs exchanged - expecting last ACK. */
		[FLOW_FORW] = {
			[TCPFC_ACK]	= POLY_TCPS_TIME_WAIT,
		},
		[FLOW_BACK] = {
			[TCPFC_ACK]	= POLY_TCPS_TIME_WAIT,
		},
	},
	[POLY_TCPS_TIME_WAIT] = {
		/* May re-open the connection as per RFC 1122. */
		[FLOW_FORW] = {
			[TCPFC_SYN]	= POLY_TCPS_SYN_SENT,
		},
	},
};

static ST_TCPAnalyzer _tcp;

/**
 * TCAZ_Init - Initialize all the fields of a small tcp analyzer
 */
void TCAZ_Init() {
        _tcp.total_syn = 0;
	_tcp.total_synack = 0;
        _tcp.total_ack = 0;
        _tcp.total_rst = 0;
        _tcp.total_fin = 0;
	_tcp.total_bad_flags = 0;
        _tcp.total_tcp_bytes = 0;
        _tcp.total_tcp_segments= 0;

	return;
}

/**
 * TCAZ_Stats - Prints staticstics related to tcp
 */
void TCAZ_Stats(FILE *out) {

	fprintf(out,"TCP analyzer statistics\n");
	fprintf(out,"\ttotal syn %ld\n",_tcp.total_syn);
	fprintf(out,"\ttotal syn/ack %ld\n",_tcp.total_synack);
	fprintf(out,"\ttotal ack %ld\n",_tcp.total_ack);
	fprintf(out,"\ttotal rst %ld\n",_tcp.total_rst);
	fprintf(out,"\ttotal fin %ld\n",_tcp.total_fin);
	fprintf(out,"\ttotal bad flags %ld\n",_tcp.total_bad_flags);
	return;
}

/**
 * TCAZ_Destroy - Destroy the fields created by the init function
 */
void TCAZ_Destroy() {
	return;
}


/**
 * TCAZ_Analyze - Analyze the TCP segment 
 *
 * @param f The ST_GenericFlow to analyze.
 */

void TCAZ_Analyze(ST_GenericFlow *f ){
	struct tcphdr *tcp = PKCX_GetTCPHeader();
	uint16_t syn = PKCX_IsTCPSyn();
	uint16_t ack = PKCX_IsTCPAck();
	uint16_t fin = PKCX_IsTCPFin();
	uint16_t rst = PKCX_IsTCPRst();
	int state = f->tcp_state_curr;
	int flags = TCPFC_INVALID;

	if(syn){
		if(ack){
			flags = TCPFC_SYNACK;
			_tcp.total_synack ++;
		}else{
			flags = TCPFC_SYN;
			_tcp.total_syn++;
		}
	}else{
		if((ack)&&(fin)){
			flags = TCPFC_FIN;
			_tcp.total_fin++;
			_tcp.total_ack++;
		}else{
			if(fin){
				flags = TCPFC_FIN;
				_tcp.total_fin++;
			}else{
				flags = TCPFC_ACK;
				_tcp.total_ack++;
			}
		}
	}

	f->tcp_state_prev = f->tcp_state_curr;
	int new_state = tcp_finite_state_machine[state][f->direction][flags];
	f->tcp_state_curr = new_state;
	if(new_state == -1)
		// Continue on the same state 
		new_state = f->tcp_state_prev;
	
	f->tcp_state_curr = new_state;
	if(rst) {
	        _tcp.total_rst ++;
        	f->aborted = 1;
        	f->tcp_state_curr = new_state = POLY_TCPS_CLOSED;
        	f->tcp_state_prev = new_state = POLY_TCPS_CLOSED;
	}

#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,
		"TCP Flow(0x%x)(%s) Flags(s(%d)a(%d)f(%d)r(%d)] state(%s) to state(%s)",
		f,f->direction ? "downstream":"upstream",
		syn,ack,fin,rst,
		tcp_states[state],tcp_states[new_state]);
#endif 
	return ;
}

