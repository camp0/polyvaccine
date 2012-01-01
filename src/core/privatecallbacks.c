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

#include "polyengine.h"
#include "callbacks.h"

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

           // send the reply && flush the connection
        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}


/* Engine Methods */
void PRCA_Method_StartEngine(DBusConnection *conn,DBusMessage *msg, void *data){
        DBusMessageIter args;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

	POEG_Start();
	
        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

        // send the reply && flush the connection
        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}

void PRCA_Method_StopEngine(DBusConnection *conn,DBusMessage *msg, void *data){
        DBusMessageIter args;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        POEG_Stop();

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

        // send the reply && flush the connection
        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}


void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data){
//	ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
        char *param = "";
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

	POEG_SetSource(param);

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

           // send the reply && flush the connection
        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}


/* Properties */
void PRCA_Property_GetState(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyEngine *p = (ST_PolyEngine*)data;
	int status = p->polyengine_status;
	char *value = polyengine_states_str[status];	

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
        return;
}

void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyEngine *p = (ST_PolyEngine*)data;
        char *value = p->source->str; 

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
        return;
}

void PRCA_Property_GetNumberValidHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
	dbus_int32_t value = 0;

	value = HTAZ_GetNumberValidHTTPHeaders();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
	return;
}

void PRCA_Property_GetNumberUnknownHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberUnknownHTTPHeaders();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}  
void PRCA_Property_GetNumberValidHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberValidHTTPParameters();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetNumberUnknownHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberUnknownHTTPParameters();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetNumberSuspiciousHTTPHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberSuspiciousHTTPHeaders();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetNumberSuspiciousHTTPParameters(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberSuspiciousHTTPParameters();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberSuspiciousSegments(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberSuspiciousSegments();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberValidSegments(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberValidSegments();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}


/* Functions for the connection manager */
void PRCA_Property_GetTotalFlowsOnFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

	value = FLPO_GetNumberFlows(p->flowpool);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetTotalSegmentOnMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

	value = MEPO_GetNumberMemorySegments(p->memorypool);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyEngine *p =(ST_PolyEngine*)data;
	dbus_int32_t value = 0;

	value = p->flowpool->total_releases;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->flowpool->total_acquires;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->flowpool->total_errors;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->total_releases;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->total_acquires;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->total_errors;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalReleaseBytes(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int64_t value = 0;

        value = p->memorypool->total_release_bytes;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}
void PRCA_Property_GetMemoryPoolTotalAcquireBytes(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p =(ST_PolyEngine*)data;
        dbus_int64_t value = 0;

        value = p->memorypool->total_acquire_bytes;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Method_IncreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
	dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

	value = MEPO_IncrementMemoryPool(p->memorypool,param);


	__CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
	return;
}

void PRCA_Method_DecreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

        value = MEPO_DecrementMemoryPool(p->memorypool,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;
}

void PRCA_Method_IncreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

        value = FLPO_IncrementFlowPool(p->flowpool,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;
}
void PRCA_Method_DecreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

	printf("yea\n");
        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);
	
	printf("decrease pool %d\n",param);
        value = FLPO_DecrementFlowPool(p->flowpool,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;

}

/* Properties of the http cache */
void PRCA_Property_GetNumberHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = HTCC_GetNumberHttpHeaders(p->httpcache); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpCacheParameters (DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = HTCC_GetNumberHttpParameters(p->httpcache);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpHeaderHits(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->httpcache->header_hits;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpHeaderFails(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->httpcache->header_fails;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetNumberHttpParameterHits(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->httpcache->parameter_hits;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpParameterFails(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        dbus_int32_t value = 0;

        value = p->httpcache->parameter_fails;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Method_AddAuthorizedHost(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyEngine *p = (ST_PolyEngine*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        char *value;

        reply = dbus_message_new_method_return(msg);

        // read the arguments
        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

	AUHT_AddHost(p->hosts,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;
}


