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
#include "nfpacket.h"

/**
 * PK_SetFlowResolution - Takes a resolution about a ST_Flow, drop or accept
 *
 * @param popr The ST_PolyProtector
 * @param f The ST_Flow
 * @param resolution must be NF_ACCEPT of NF_DROP
 *
 */
void NFPK_SetFlowResolution(ST_PolyProtector *popr,ST_Flow *f, int resolution)
{
        nfq_set_verdict(popr->qh, f->id, resolution, 0, NULL);
        return;
}

ST_Flow *NFPK_GetFlow(GHashTable *t,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport){
        gpointer object;
        struct in_addr a,b;

        a.s_addr = saddr;
        b.s_addr = daddr;

        unsigned long h = (saddr^sport^protocol^daddr^dport);

        DEBUG2("first lookup:[%s:%d:%d:%s:%d]\n",inet_ntoa(a),sport,protocol,inet_ntoa(b),dport);

        object = g_hash_table_lookup(t,GINT_TO_POINTER(h));
        if (object != NULL){
                return (ST_Flow*)object;
        }

        h = (daddr^dport^protocol^saddr^sport);

        DEBUG2("second lookup:[%s:%d:%d:%s:%d]\n",inet_ntoa(b),dport,protocol,inet_ntoa(a),sport);

        object = g_hash_table_lookup(t,GINT_TO_POINTER(h));
        if (object != NULL){
                return (ST_Flow*)object;
        }

        return NULL;
}

void NFPK_InsertFlow(GHashTable *t,ST_Flow *flow){
        struct in_addr a,b;

        a.s_addr = flow->saddr;
        b.s_addr = flow->daddr;

        unsigned long h = (flow->saddr^flow->sport^6^flow->daddr^flow->dport);

        DEBUG2("insert flow(0x%x) hash(%lu) [%s:%d:%d:%s:%d]\n",flow,h,
                inet_ntoa(a),flow->sport,6,inet_ntoa(b),flow->dport);

        g_hash_table_insert(t,GINT_TO_POINTER(h),flow);
        return;
}


/**
 * PK_HandlerPacket - Handler Network Packets
 *
 * @param qh main handerl of libnetfilter 
 * @param nfmsg the message
 * @param nfa the data
 * @param data user data for handler
 *
 */
int NFPK_HandlerPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	ST_PolyProtector *popr = (ST_PolyProtector*)data;
        struct nfqnl_msg_packet_hdr *ph;
        int id = 0, status = 0;
        int ret;
        int sizepkt;
        //long total;
        struct iphdr *ip;
        struct tcphdr *tcp;
        struct in_addr a,b;
        ST_Flow *f;
        unsigned char *payload;
        u_int32_t devin, devout;
        char ip_src[16],ip_dst[16];
        struct in_addr in_ip;
        char *veredict_str;

        ph = nfq_get_msg_packet_hdr(nfa);
        if (ph) {
                id = ntohl(ph->packet_id);
                devin = nfq_get_indev(nfa);
                devout = nfq_get_outdev(nfa);
                sizepkt = nfq_get_payload(nfa, &payload);

                /* We only want inbound forwarded packets */
		//if(devin == popr->dev_index) {
		if(devout == popr->dev_index) {
        		popr->total_inbound_packets ++;
                        ip = (struct iphdr *) (payload);
                        if ((ip->version == IPVERSION)&&(ip->protocol == IPPROTO_TCP)) {
				popr->total_tcp_packets ++;
                                tcp = (struct tcphdr *) (payload + IPVERSION * ip->ihl);
                                if (tcp->psh) { /* This packet must be autorized */
					popr->total_tcp_segments++;
        				a.s_addr = ip->saddr;
        				b.s_addr = ip->daddr;
        				DEBUG0("Segment(%u:%u):[%s:%d:%d:%s:%d]\n",
						tcp->seq,tcp->ack_seq,inet_ntoa(a),htons(tcp->source),6,inet_ntoa(b),htons(tcp->dest));	
				
					/* check if the flow already exists */
					f = NFPK_GetFlow(popr->table,ip->saddr,tcp->source,6,ip->daddr,tcp->dest);
					if (f == NULL) { // there is no flow attached
						f = NFPO_GetFlow(popr->pool); 
						if (f == NULL) { // Not enought memory to handler, drop the packet
                					nfq_set_verdict(popr->qh, id, NF_DROP, 0, NULL);
							return 0;
						}
						FLOW_SetFlowId(f,ip->saddr,tcp->source,ip->daddr,tcp->dest);
						NFPK_InsertFlow(popr->table,f);
					}else{ // The flow exits	
                                        	/* check if its a retransmision */
						if(f->seq == tcp->seq) {
							nfq_set_verdict(popr->qh, id, NF_DROP, 0, NULL);
        						DEBUG0("Retransmision segment,droping\n");
							popr->tcp_retransmition_drop_segments++;
							return 0;
						}
					}

        				DEBUG0("Waiting for authorization\n");
					FLOW_SetSequenceNumber(f,tcp->seq);
                                        return 0;
                                }
                        }
                }
                nfq_set_verdict(popr->qh, id, NF_ACCEPT, 0, NULL);
                return 0;
        } else {
                fprintf(stdout, "NFQUEUE: can't get msg packet header.\n");
                return 1;       // from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
        }
        return 0;
}

/**
 * NFPK_CloseNfq - Close the Netfilter api
 *
 */
void NFPK_CloseNfq(ST_PolyProtector *popr)
{
        nfq_destroy_queue(popr->qh);
        nfq_close(popr->h);
	return;
}

/**
 * NFPK_InitNfq - The main function thats gets the Network packets
 *
 */
int NFPK_InitNfq(ST_PolyProtector *popr){
        struct nfnl_handle *nh;
        int fd, rv;
        char buf[MAX_PKT_BUFFER_SIZE];

        popr->h = nfq_open();
        if (!popr->h) {
                perror("nfq_open");
                return -1;
        }

        if (nfq_unbind_pf(popr->h, AF_INET) < 0) {
                perror("nfq_unbind_pf");
        }

        if (nfq_bind_pf(popr->h, AF_INET) < 0) {
                perror("nfq_bind_pf");
              	return -1; 
        }

        popr->qh = nfq_create_queue(popr->h, 0, &NFPK_HandlerPacket, popr);
        if (!popr->qh) {
                perror("nfq_create_queue");
              	return -1; 
        }

        if (nfq_set_mode(popr->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                perror("nfq_set_mode");
              	return -1; 
        }
        nh = nfq_nfnlh(popr->h);
        fd = nfnl_fd(nh);

        /*while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                nfq_handle_packet(h, buf, rv);
        }
	*/
        //PK_CloseNfq();
        return fd;
}

