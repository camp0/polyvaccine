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

#include "polyfilter.h"
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

	POFR_Start();
	
        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

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

        POFR_Stop();

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}


void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data){
        DBusMessageIter args;
        char *param = "";
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

	POFR_SetSource(param);

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);

        return;
}

void PRCA_Method_SetMode(DBusConnection *conn,DBusMessage *msg, void *data){
        DBusMessageIter args;
        char *param = "";
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);

        POFR_SetMode(param);

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

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
	ST_PolyFilter *p = (ST_PolyFilter*)data;
	int status = p->polyfilter_status;
	char *value = polyfilter_states_str[status];	

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
        return;
}

void PRCA_Property_GetMode(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        int status = p->mode;
        char *value = polyfilter_modes_str[status];

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
        return;
}

void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyFilter *p = (ST_PolyFilter*)data;
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
void PRCA_Property_GetTotalReleaseConnections(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
	dbus_int32_t value = p->conn->releases;

	__CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
	return;
}

void PRCA_Property_GetTotalCurrentConnections(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = p->conn->current_connections;

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalInsertConnections(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
	dbus_int32_t value = p->conn->inserts;

	__CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalTimeoutConnections(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
	dbus_int32_t value = p->conn->expiretimers;

	__CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalFlowsOnFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

	value = FLPO_GetNumberFlows(p->flowpool);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetTotalSegmentOnMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

	value = MEPO_GetNumberMemorySegments(p->memorypool);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyFilter *p =(ST_PolyFilter*)data;
	dbus_int32_t value = 0;

	value = p->flowpool->pool->total_releases;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->flowpool->pool->total_acquires;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetFlowPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->flowpool->pool->total_errors;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->pool->total_releases;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->pool->total_acquires;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->memorypool->pool->total_errors;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetMemoryPoolTotalReleaseBytes(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int64_t value = 0;

        value = p->memorypool->total_release_bytes;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}
void PRCA_Property_GetMemoryPoolTotalAcquireBytes(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int64_t value = 0;

        value = p->memorypool->total_acquire_bytes;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT64,(void*)value);
        return;
}

void PRCA_Method_IncreaseMemoryPool(DBusConnection *conn,DBusMessage *msg, void *data){
	ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
	dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

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
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

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
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

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
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int value = 1;

        reply = dbus_message_new_method_return(msg);

        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &param);
	
        value = FLPO_DecrementFlowPool(p->flowpool,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;

}

/* Methods of the http cache */

void PRCA_Method_GetHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
	GList *l = NULL; 
        DBusMessageIter iter;
        DBusMessage *reply = NULL;
	int items = 0;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init(reply, &iter);
        dbus_message_iter_init_append(reply, &iter);

	// TODO
	//l = g_hash_table_get_keys(p->httpcache->header_cache);
	while(l != NULL) {
		/** TODO 
		 * Dbus have a bug or some limit, so only 255 items of 
		 * the cache are send.
		 */
		items ++;
		if(items >255) break;
        	dbus_message_iter_append_basic(&iter,DBUS_TYPE_STRING,&(l->data));
		l = g_list_next(l);
	}

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
	return;
}

void PRCA_Method_GetHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
	GList *l = NULL;
        DBusMessageIter iter;
        dbus_int32_t param;
        DBusMessage *reply = NULL;
        int items = 0;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init(reply, &iter);
        dbus_message_iter_init_append(reply, &iter);

	// TODO
        //l = g_hash_table_get_keys(p->httpcache->parameter_cache);

        while(l != NULL) {
		 /** TODO 
                 * Dbus have a bug or some limit, so only 255 items of 
                 * the cache are send.
                 */
		items++;
		if(items>255)break;
                dbus_message_iter_append_basic(&iter,DBUS_TYPE_STRING,&(l->data));
                l = g_list_next(l);
        }

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
        return;
}

void PRCA_Method_AddHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
        dbus_int32_t ret = 1;
        DBusMessage *reply = NULL;
        char *value;

        reply = dbus_message_new_method_return(msg);

        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &value);

	HTAZ_AddHeaderToCache(value,NODE_TYPE_DYNAMIC);
	//CACH_AddHeaderToCache(p->httpcache,value,NODE_TYPE_DYNAMIC);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,ret);
	return;
}

void PRCA_Method_AddHttpCacheParameters(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
        DBusMessageIter args;
        dbus_int32_t ret = 1;
        DBusMessage *reply = NULL;
        char *value;

        reply = dbus_message_new_method_return(msg);

        if (!dbus_message_iter_init(msg, &args))
                fprintf(stderr, "Message has no arguments!\n");
        else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
                fprintf(stderr, "Argument is not string!\n");
        else
                dbus_message_iter_get_basic(&args, &value);

	HTAZ_AddParameterToCache(value,NODE_TYPE_DYNAMIC);
//	CACH_AddParameterToCache(p->httpcache,value,NODE_TYPE_DYNAMIC);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,ret);
        return;
}

/* Properties of the http cache */
void PRCA_Property_GetNumberHttpCacheHeaders(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberHeaders(); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpCacheParameters (DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetNumberParameters();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpHeaderHits(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetHeaderHits(); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpHeaderFails(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetHeaderFails(); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}
void PRCA_Property_GetNumberHttpParameterHits(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetParameterHits(); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberHttpParameterFails(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = HTAZ_GetParameterFails(); 
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Method_AddAuthorizedHost(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
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

void PRCA_Method_RemoveAuthorizedHost(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p = (ST_PolyFilter*)data;
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

        AUHT_RemoveHost(p->hosts,param);

        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
        return;
}


/* Functions for the user manager */
void PRCA_Property_GetTotalReleaseUsers(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = p->users->releases;

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetTotalCurrentUsers(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = p->users->current_users;

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalInsertUsers(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = p->conn->inserts;

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalTimeoutUsers(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = p->users->expiretimers;

        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

        return;
}

void PRCA_Property_GetTotalUsersOnUserPool(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

	value = USPO_GetNumberUsers(p->userpool);
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetUserPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->userpool->pool->total_releases;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetUserPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->userpool->pool->total_acquires;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetUserPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
        ST_PolyFilter *p =(ST_PolyFilter*)data;
        dbus_int32_t value = 0;

        value = p->userpool->pool->total_errors;
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

/* Functions related to the graph cache */
void PRCA_Property_GetNumberGraphCacheLinks(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

	value = DSAZ_GetGraphCacheLinks();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
	return;
}

void PRCA_Property_GetNumberGraphCacheHits(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

	value = DSAZ_GetGraphCacheLinkHits();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberGraphCacheFails(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

	value = DSAZ_GetGraphCacheLinkFails();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberPathCachePaths(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = DSAZ_GetPathCachePaths();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberPathCacheHits(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = DSAZ_GetPathCachePathHits();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}

void PRCA_Property_GetNumberPathCacheFails(DBusConnection *conn,DBusMessage *msg, void *data){
        dbus_int32_t value = 0;

        value = DSAZ_GetPathCachePathFails();
        __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
        return;
}


void PRCA_Method_AddLinkToGraphCache(DBusConnection *conn,DBusMessage *msg, void *data){
        DBusMessageIter args;
        ST_PolyFilter *p = (ST_PolyFilter*)data;
	DBusMessage *reply = NULL;
        DBusError error;
	char *urisrc = NULL;
	char *uridst = NULL;
	dbus_int32_t cost = 0;       
	dbus_int32_t ret = 0;
 
	dbus_error_init(&error);
        
	reply = dbus_message_new_method_return(msg);

        /*
         * Receives a Link from a external process
         * uri1,uri2,cost
         */

        dbus_message_get_args(msg,&error,
		DBUS_TYPE_STRING,&urisrc,
		DBUS_TYPE_STRING,&uridst,
                DBUS_TYPE_INT32,&cost,
                DBUS_TYPE_INVALID);

	if((urisrc)&&(uridst)){
		// TODO
		//GACH_AddLink(p->graphcache,urisrc,uridst,cost);
		ret = 1;
	}
        __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,ret);
	return;
}

