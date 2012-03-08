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

#include "polydetector.h"
#include "callbacks.h"
#include <stdio.h>
#include <glib.h>
#include "../core/trustoffset.h"

/* Used for the Property Dbus interface */
void __CMD_GenericPropertyGetter(DBusConnection *conn,DBusMessage *msg,int type, void *value) {
        DBusMessageIter args;
        DBusMessage *reply = NULL;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        if (!dbus_message_iter_append_basic(&args, type, &value)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}

void __CMD_GenericMethodResponse(DBusConnection *conn,DBusMessage *reply,DBusMessageIter *args,int type, void *value){

        dbus_message_iter_init(reply, args);
        dbus_message_iter_init_append(reply, args);
        dbus_message_iter_append_basic(args,type,&value);

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}


void PRCA_Signaling_AnalyzeSegment(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyDetector *p = (ST_PolyDetector*)data;
	DBusMessageIter args;
	unsigned char *buffer;
	int ret,i;
	dbus_int32_t length,value,s_ret,e_ret; 
	DBusError error;
	ST_TrustOffsets t_off;
	unsigned char *array = p->buffer;
	dbus_uint32_t hash;
	dbus_uint32_t seq;
	dbus_int32_t veredict;
	dbus_int32_t *d_start_off;
	dbus_int32_t *d_end_off;
	int start_offset[8];
	int end_offset[8];
	
	dbus_error_init(&error);

	memset(p->buffer,0,MAX_DBUS_SEGMENT_BUFFER);
	/*
	 * Receives a tcp suspicious segment with the following information send by the Filter engine.
	 *
	 * 1 - array byte (the suspicious buffer)
	 * 2 - hash of the flow.
	 * 3 - sequence number of the flow
	 * 4 - start and end trusted offsets for execution.
	 */

	dbus_message_get_args(msg,&error,
		DBUS_TYPE_ARRAY,DBUS_TYPE_BYTE,&array,&length,
		DBUS_TYPE_UINT32,&hash,
		DBUS_TYPE_UINT32,&seq,
		DBUS_TYPE_ARRAY,DBUS_TYPE_INT32,&d_start_off,&s_ret,
		DBUS_TYPE_ARRAY,DBUS_TYPE_INT32,&d_end_off,&e_ret,
		DBUS_TYPE_INVALID);

	LOG(POLYLOG_PRIORITY_INFO,
		"receive buffer lenght(%d)hash(%lu)seq(%lu)s_off_len(%d)e_off_len(%d)",
		length,hash,seq,s_ret,e_ret);

	TROF_SetStartOffsets(&t_off,d_start_off);
	TROF_SetEndOffsets(&t_off,d_end_off);

/*	for (i = 0;i<8;i++) {
		start_offset[i] = d_start_off[i];
		end_offset[i] = d_end_off[i];
	} 
	for (i =0;i<8;i++) fprintf(stdout,"(%d)",t_off.offsets_start[i]);
	fprintf(stdout,"\n");
	for (i =0;i<8;i++) fprintf(stdout,"[%d]",t_off.offsets_end[i]);
*/
	if(p->show_received_payload) {
		fprintf(stdout,"Payload received:\n");
		printfhex(array,length);
		fprintf(stdout,"\n");
	}

	ret = SYSU_AnalyzeSegmentMemory(array,length,&t_off);
	if(ret)
		p->shellcodes_detected++;
	SYSU_DestroySuspiciousSyscalls();

	/* For some reason if the -b option is set the dbus sends a 
           Disconect message and the pvde exists. This should be 
	   fixed one day :D
        */
	if(p->block_syscalls == FALSE) 
		PODS_SendVerifiedSegment(conn,
			"/polyvaccine/protector","polyvaccine.protector.veredict","Veredict",
                	seq,hash,ret);
	p->executed_segments ++;
	return;
}

void PRCA_Property_GetNumberExecutedSegments(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyDetector *p = (ST_PolyDetector*)data;
        dbus_int32_t value = 0;

        value = p->executed_segments;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberShellcodesDetected(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyDetector *p = (ST_PolyDetector*)data;
        dbus_int32_t value = 0;

        value = p->shellcodes_detected;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
	return;
}
