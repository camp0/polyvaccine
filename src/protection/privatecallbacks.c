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

#include "polyprotector.h"
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

void PRCA_Signaling_AuthorizeSegment(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyProtector *p = (ST_PolyProtector*)data;
	ST_Flow *f;
        DBusMessageIter args;
        dbus_int32_t hash1,hash2;
        dbus_int32_t veredict;
        DBusError error;

        dbus_error_init(&error);

        dbus_message_get_args(msg,&error,
		DBUS_TYPE_INT32,&hash1,
		DBUS_TYPE_INT32,&hash2,
		DBUS_TYPE_INT32,&veredict,
		DBUS_TYPE_INVALID);

	DEBUG0("verdict %d for flow (%x,%x)\n",veredict,hash1,hash2);

	f = NFPK_GetFlowByHash(p->table,hash1,hash2);
	if (f) {
		NFPK_SetFlowResolution(p,f, veredict);	
	}
        return;
}


void PRCA_Property_GetTotalInboundPackets(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyProtector *p = (ST_PolyProtector*)data;
        dbus_int64_t value = 0;

        value = p->total_inbound_packets;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Property_GetTotalTcpPackets(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyProtector *p = (ST_PolyProtector*)data;
        dbus_int64_t value = 0;

        value = p->total_tcp_packets;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Property_GetTotalTcpSegments(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyProtector *p = (ST_PolyProtector*)data;
        dbus_int64_t value = 0;

        value = p->total_tcp_segments;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Property_GetTcpRetransmitionDropSegments(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyProtector *p = (ST_PolyProtector*)data;
        dbus_int64_t value = 0;

        value = p->tcp_retransmition_drop_segments;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Property_GetTcpDropSegments(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyProtector *p = (ST_PolyProtector*)data;
        dbus_int64_t value = 0;

        value = p->tcp_drop_segments;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}


