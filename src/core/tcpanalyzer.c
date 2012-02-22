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
#include "debug.h"

/*
enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING    now a valid state 
};
*/

static char *tcp_states [] = {
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"TCP_CLOSING"
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

	_tcp.logger = log4c_category_get(POLYVACCINE_FILTER_TCP_INTERFACE);
	return;
}

/**
 * TCAZ_Stats - Prints staticstics related to tcp
 */
void TCAZ_Stats(void) {

	fprintf(stdout,"TCP analyzer statistics\n");
	fprintf(stdout,"\ttotal syn %ld\n",_tcp.total_syn);
	fprintf(stdout,"\ttotal syn/ack %ld\n",_tcp.total_synack);
	fprintf(stdout,"\ttotal ack %ld\n",_tcp.total_ack);
	fprintf(stdout,"\ttotal rst %ld\n",_tcp.total_rst);
	fprintf(stdout,"\ttotal fin %ld\n",_tcp.total_fin);
	fprintf(stdout,"\ttotal bad flags %ld\n",_tcp.total_bad_flags);
	return;
}

/**
 * TCAZ_Destroy - Destroy the fields created by the init function
 */
void TCAZ_Destroy() {
	return;
}



void TCAZ_HandlerSyn(ST_GenericFlow *f){

	if(f->tcp_state_prev == TCP_CLOSE && f->tcp_state_curr == TCP_CLOSE &&
		PKCX_IsTCPSyn() == 1 && PKCX_IsTCPAck() == 0){
		/* First syn from client */
		f->tcp_state_prev = TCP_CLOSE;
		f->tcp_state_curr = TCP_SYN_SENT;
        	_tcp.total_syn ++;
		return;
	}
	if(f->tcp_state_curr != TCP_SYN_SENT && f->tcp_state_prev != TCP_CLOSE &&
		PKCX_IsTCPAck() == 0){
		_tcp.total_bad_flags ++;
		// no syn/ack packet
		return;
	}
	// syn/ack received
	_tcp.total_synack ++;
	f->tcp_state_prev = f->tcp_state_curr;
	f->tcp_state_curr = TCP_SYN_RECV;
	return;	
}

void TCAZ_HandlerAck(ST_GenericFlow *f){

	//printf("ACK %s -> %s \n",
	//	tcp_states[f->tcp_state_prev],tcp_states[f->tcp_state_curr]);
	if(f->tcp_state_prev == TCP_SYN_SENT && f->tcp_state_curr == TCP_SYN_RECV &&
		PKCX_IsTCPAck() == 1) {
		// sequence check
		f->tcp_state_prev = TCP_ESTABLISHED;
		f->tcp_state_curr = TCP_ESTABLISHED;
		_tcp.total_ack ++;
		return;
	}
        if(f->tcp_state_curr == TCP_LAST_ACK) {
                f->tcp_state_prev = TCP_CLOSE;
                f->tcp_state_curr = TCP_CLOSE;
		return;
        }
	if(f->tcp_state_curr == TCP_FIN_WAIT1) {
		f->tcp_state_prev = f->tcp_state_curr;
		f->tcp_state_curr = TCP_FIN_WAIT2;
		return;
	}
	f->tcp_state_prev = f->tcp_state_curr;
	return;
}


void TCAZ_HandlerFin(ST_GenericFlow *f){

	_tcp.total_fin ++;
	if(PKCX_IsTCPAck() == 0) {
		if(f->tcp_state_curr == TCP_SYN_RECV){
			f->tcp_state_prev = f->tcp_state_curr;
			f->tcp_state_curr = TCP_FIN_WAIT1;
			_tcp.total_fin ++;
			return; 
		} 
		if(f->tcp_state_curr == TCP_ESTABLISHED) {
			f->tcp_state_prev = f->tcp_state_curr;
			f->tcp_state_curr = TCP_FIN_WAIT1;
			return;
		}	
	}else{
		if(f->tcp_state_curr == TCP_ESTABLISHED) {
			f->tcp_state_prev = f->tcp_state_curr;
			f->tcp_state_curr = TCP_CLOSE_WAIT;
			return;
		}
		if(f->tcp_state_curr == TCP_CLOSE_WAIT) {
			f->tcp_state_prev = f->tcp_state_curr;
			f->tcp_state_curr = TCP_LAST_ACK;
			return;
		}
		if(f->tcp_state_curr == TCP_FIN_WAIT2) {
			f->tcp_state_prev = f->tcp_state_curr;
			f->tcp_state_curr = TCP_TIME_WAIT;
			return;
		}
	}
	f->tcp_state_prev = f->tcp_state_curr;
}

void TCAZ_HandlerRst(ST_GenericFlow *f){

	_tcp.total_rst ++;
	f->aborted = 1;
	//if(f->tcp_state_curr == TCP_SYN_RECV){
	f->tcp_state_curr = TCP_CLOSE;
	f->tcp_state_prev = TCP_CLOSE;
//	}
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
	short prev_state = f->tcp_state_curr;
	// TCP stack state machine
	if(syn) {
		TCAZ_HandlerSyn(f);
	}else if(rst){
		TCAZ_HandlerRst(f);
	}else if(ack){
		TCAZ_HandlerAck(f);
	}

	if(f->aborted != 1) 
		if(fin)
			TCAZ_HandlerFin(f);

	log4c_category_log(_tcp.logger,LOG4C_PRIORITY_DEBUG,
		"TCP Flow(0x%x) Flags(s(%d)a(%d)f(%d)r(%d)] change state(%s) to state(%s)",
		f,
		syn,ack,fin,rst,
		tcp_states[prev_state],tcp_states[f->tcp_state_curr]);
	return ;
}

