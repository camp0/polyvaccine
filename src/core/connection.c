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

#include "connection.h"
#include "httpflow.h"


void COMN_SetFlowPool(ST_Connection *conn,ST_FlowPool *flowpool){
	conn->flowpool = flowpool;
}

void COMN_SetMemoryPool(ST_Connection *conn,ST_MemoryPool *mempool){
	conn->mempool = mempool;
}


gint flow_cmp(ST_HttpFlow *f1, ST_HttpFlow *f2) {
        if (f1->current_time.tv_sec > f2->current_time.tv_sec)
                return 1;
        else
                return 0;
}


void COMN_InsertConnection(ST_Connection *conn,ST_HttpFlow *flow,unsigned long *hash){
        struct in_addr a,b;

        a.s_addr = flow->saddr;
        b.s_addr = flow->daddr;

        unsigned long h = (flow->saddr^flow->sport^6^flow->daddr^flow->dport);
	(*hash) = h;

 //       DEBUG2("insert flow(0x%x) hash(%lu) [%s:%d:%d:%s:%d]\n",flow,h,
  //              inet_ntoa(a),flow->sport,6,inet_ntoa(b),flow->dport);

        g_hash_table_insert(conn->table,GINT_TO_POINTER(h),flow);
	conn->timers = g_list_insert_sorted(conn->timers,flow,(GCompareFunc)flow_cmp);
	return;
}

void COMN_UpdateTimers(ST_Connection *conn,struct timeval *currenttime){
        GList *f_update = NULL;
        GList *current = NULL;
        ST_HttpFlow *flow = NULL;
        //struct timeval *t = NULL;
	ST_MemorySegment *seg = NULL;

        while((current = g_list_first(conn->timers)) != NULL) {
                flow =(ST_HttpFlow*)current->data;
                conn->timers = g_list_remove_link(conn->timers,current);

//                DEBUG1("Checkin timer for flow(0x%x)secs(%d)curr(%d)\n",flow,flow->current_time.tv_sec,currenttime->tv_sec);
                if(flow->current_time.tv_sec + conn->inactivitytime <= currenttime->tv_sec) {
                        /* The timer expires */
                        DEBUG0("Expire timer for flow(0x%x)secs(%d)curr(%d)\n",flow,flow->current_time.tv_sec,currenttime->tv_sec);

                        unsigned long h = (flow->saddr^flow->sport^6^flow->daddr^flow->dport);
                        if(g_hash_table_remove(conn->table,GINT_TO_POINTER(h)) == FALSE) {
                                h = (flow->daddr^flow->dport^6^flow->saddr^flow->sport);
                                g_hash_table_remove(conn->table,GINT_TO_POINTER(h));
                        }
                        if((conn->flowpool)&&(conn->mempool)){
				seg = flow->memhttp;
				flow->memhttp = NULL;
                                DEBUG0("Releasing flow(0x%x)segment(0x%x) to flowpool(0x%x)memorypool(0x%x)\n",
					flow,seg,conn->flowpool,conn->mempool);
				MEPO_AddMemorySegment(conn->mempool,seg);
				//flow->memhttp = NULL; // Deattach the reference to the flow	
				FLPO_AddFlow(conn->flowpool,flow);
				//printf("leay\n");
                        }
                        conn->expiretimers++; 
                        continue;
                }
                f_update = g_list_insert_sorted(f_update,flow,(GCompareFunc)flow_cmp);
        }
        conn->timers = g_list_concat(f_update,conn->timers);
        return;
}


static gboolean COMN_DestroyCallback(gpointer v) {
	ST_HttpFlow *f = (ST_HttpFlow*)v;

	MESG_Destroy(f->memhttp);
        g_free(f);
        return TRUE;
}

ST_Connection *COMN_Init() {
	ST_Connection *conn= NULL;

	conn =(ST_Connection*)g_new(ST_Connection,1);
	conn->table = g_hash_table_new(g_direct_hash,g_direct_equal);
	//conn->table = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,COMN_DestroyCallback);
	conn->timers = NULL;
	//conn->inactivitytime = 10;
	conn->inactivitytime = 180;
	conn->expiretimers = 0;
	conn->flowpool = NULL;
	conn->mempool = NULL;
	return conn;
};

void COMN_Destroy(ST_Connection *conn) {
        g_hash_table_destroy(conn->table);
        g_list_free(conn->timers);
     	g_free(conn); 
}

ST_HttpFlow *COMN_FindConnection(ST_Connection *conn,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport,unsigned long *hash){
        gpointer object;
        struct in_addr a,b;

        a.s_addr = saddr;
        b.s_addr = daddr;

        unsigned long h = (saddr^sport^protocol^daddr^dport);

//        DEBUG2("first lookup(%lu):[%s:%d:%d:%s:%d]\n",h,inet_ntoa(a),sport,protocol,inet_ntoa(b),dport);

        object = g_hash_table_lookup(conn->table,GINT_TO_POINTER(h));
        if (object != NULL){
		(*hash) = h;
                return (ST_HttpFlow*)object;
        }

        h = (daddr^dport^protocol^saddr^sport);

 //       DEBUG2("second lookup(%lu):[%s:%d:%d:%s:%d]\n",h,inet_ntoa(b),dport,protocol,inet_ntoa(a),sport);

        object = g_hash_table_lookup(conn->table,GINT_TO_POINTER(h));
        if (object != NULL){
		(*hash) = h;
                return (ST_HttpFlow*)object;
        }

        return NULL;
}

