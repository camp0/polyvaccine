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

#define MAX_PUBLIC_INTERFACES 1

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
	dbus_int32_t length,value; 
	DBusError error;
	unsigned char *array = p->buffer;
	dbus_uint32_t hash;
	dbus_uint32_t seq;
	dbus_int32_t veredict;

	dbus_error_init(&error);

	memset(p->buffer,0,MAX_DBUS_SEGMENT_BUFFER);
	/*
	 * Receives a tcp suspicious segment with the following information send by the Filter engine.
	 *
	 * 1 - array byte (the suspicious buffer)
	 * 2 - hash of the flow.
	 * 3 - sequence number of the flow
	 */
	dbus_message_get_args(msg,&error,
		DBUS_TYPE_ARRAY,DBUS_TYPE_BYTE,&array,&length,
		DBUS_TYPE_UINT32,&hash,
		DBUS_TYPE_UINT32,&seq,
		DBUS_TYPE_INVALID);

	DEBUG0("receive buffer lenght(%d)hash(%lu)seq(%lu)\n",
		length,hash,seq);
	printf("buffer size = %d value = %d\n",length,value);
	for(i = 0;i<16;i++){
		printf("0x%x ",array[i]);
		if ((i %16) ==0)printf("\n");
	} 	
	printf("\n");
	
	ret = SYSU_AnalyzeSegmentMemory(array,length,0);
	if(ret)
		p->shellcodes_detected++;
	SYSU_DestroySuspiciousSyscalls();
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
