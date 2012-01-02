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

#include "polydbus.h"
#include "debug.h"
#include "callbacks.h"

static ST_PolyDbus polybus;

/**
 * PODS_Init- Initalize the dbus wrapper library. 
 *
 */
void PODS_Init(){
	polybus.total_watches = 0;
	polybus.public_callbacks = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	polybus.private_callbacks = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);;
	polybus.interfaces = NULL;
	DEBUG0("Dbus object(0x%x)\n",&polybus);
	return;
}

/**
 * PODS_AddInterface
 *
 */

void PODS_AddInterface(ST_Interface *iface){
	polybus.interfaces = g_list_append(polybus.interfaces,iface);
}

void PODS_AddPublicCallback(ST_Callback *call){
	g_hash_table_insert(polybus.public_callbacks,g_strdup(call->name),call);
	return;
}

void PODS_AddPrivateCallback(ST_Callback *call){
	g_hash_table_insert(polybus.private_callbacks,g_strdup(call->name),call);
	return;
}

void PODS_Destroy() {
	g_hash_table_destroy(polybus.public_callbacks);
	g_hash_table_destroy(polybus.private_callbacks);
	return;
}

int PODS_GetTotalActiveDescriptors() {
	return polybus.total_watches;
}

int PODS_GetDescriptorByIndex(int i){
	return polybus.pollfds[i].fd;
}

DBusWatch *PODS_GetWatchByIndex(int i) {
	return polybus.watches[i];
}

int PODS_GetEventsByIndex(int i){
	return polybus.pollfds[i].events;
}

void PODS_ExecuteCallback(GHashTable *h, DBusConnection *c,DBusMessage *msg,char *key, void *data) {
        ST_Callback *callback = NULL;
        const char *destination = dbus_message_get_destination(msg);
        const char *interface = dbus_message_get_interface(msg);
        const char *member = dbus_message_get_member(msg);
        const char *path = dbus_message_get_path(msg);

        DEBUG0("receive message from '%s' on object (0x%x)callback(%s)\n",interface,h,key);
        callback = (ST_Callback*)g_hash_table_lookup(h,(gchar*)key);
        if(callback != NULL) {
                DEBUG0("method found '%s' callback(0x%x)\n",key,callback);
                callback->function(c,msg,data);
        }else{
                DEBUG0("method not found '%s'\n",key);
        }
	return;
}

DBusHandlerResult DB_FilterDbusFunctionMessage(DBusConnection *c, DBusMessage *msg, void *data){
	register int i;
        const char *destination = dbus_message_get_destination(msg);
        const char *interface = dbus_message_get_interface(msg);
        const char *member = dbus_message_get_member(msg);
        const char *path = dbus_message_get_path(msg);

        DEBUG1("i(%s)d(%d)p(%s)m(%s)\n",interface,destination,path,member);

        if (dbus_message_is_method_call (msg, "org.freedesktop.DBus.Introspectable", "Introspect")) {
		PODS_Method_Instrospect(c,msg,data);
                return DBUS_HANDLER_RESULT_HANDLED;
        }
        if (dbus_message_is_method_call (msg,"org.freedesktop.DBus.Properties","Get")) {
                char *iface = "";
                char *property = "";
                DBusError err;

                dbus_error_init(&err);
                dbus_message_get_args(msg,&err,DBUS_TYPE_STRING,&iface,DBUS_TYPE_STRING,&property);
                PODS_ExecuteCallback(polybus.public_callbacks,c,msg,property,data);
                return DBUS_HANDLER_RESULT_HANDLED;
        } 
	GList *item = polybus.interfaces;
	while ( item != NULL) {
		char *iface = ((ST_Interface*)item->data)->name; //ST_PublicInterfaces[i].name;
		if(strncmp(iface,interface,strlen(iface)) == 0) {
        		//DEBUG0("Message for '%s'd(%d)p(%s)m(%s)\n",interface,destination,path,member);
			PODS_ExecuteCallback(polybus.public_callbacks,c,msg,member,data);
                	return DBUS_HANDLER_RESULT_HANDLED;
		}
		item = g_list_next(item);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

void PODS_Handler(DBusConnection *conn,short events, DBusWatch *watch)
{
        unsigned int flags = 0;

        if (events & POLLIN)
                flags |= DBUS_WATCH_READABLE;
        if (events & POLLOUT)
                flags |= DBUS_WATCH_WRITABLE;
        if (events & POLLHUP)
                flags |= DBUS_WATCH_HANGUP;
        if (events & POLLERR)
                flags |= DBUS_WATCH_ERROR;

        while (!dbus_watch_handle(watch, flags)) {
                printf("dbus_watch_handle needs more memory/n");
                sleep(1);
        }

        dbus_connection_ref(conn);
        while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS);
        dbus_connection_unref(conn);
}


static dbus_bool_t _addWatchFunction(DBusWatch *watch, void *data){
        short cond = POLLHUP | POLLERR;
        int fd;
        unsigned int flags;

        //printf(" add watch %p on slot %d\n", (void*)watch,total_watches);
        fd = dbus_watch_get_fd(watch);
        flags = dbus_watch_get_flags(watch);

        if (flags & DBUS_WATCH_READABLE)
                cond |= POLLIN;
        if (flags & DBUS_WATCH_WRITABLE)
                cond |= POLLOUT;

        polybus.pollfds[polybus.total_watches].fd = fd;
        polybus.pollfds[polybus.total_watches].events = cond;
        polybus.pollfds[polybus.total_watches].revents = 0;
        polybus.watches[polybus.total_watches] = watch;
        polybus.total_watches ++;
        return 1;
}

static void _removeWatchFunction(DBusWatch *watch, void *data){
       	register int i;
 
	DEBUG0("remove dbus watch %p\n", (void*)watch);
        for (i = 0; i < polybus.total_watches; i++) {
                if (polybus.watches[i] == watch) {
			memset(&polybus.pollfds[i],0,sizeof(polybus.pollfds[i]));
			polybus.watches[i] = NULL;
			polybus.total_watches --;	
                        return;
                }
        }
	return;
}

DBusConnection *PODS_Connect(char *interface,void *engine) {
	DBusConnection *bus;
        DBusError err;
        int ret;
        char* sigvalue;

        dbus_error_init(&err);
        bus = dbus_bus_get(DBUS_BUS_SESSION, &err);
        if (dbus_error_is_set(&err)) {
                fprintf(stderr, "Connection Error (%s)\n", err.message);
                dbus_error_free(&err);
        }
        if (NULL == bus) {
                fprintf(stderr, "Connection to dbus failed\n");
                return NULL;
        }

        ret = dbus_bus_request_name(bus,interface, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
        if (dbus_error_is_set(&err)) {
                fprintf(stderr, "Name Error (%s)\n", err.message);
                dbus_error_free(&err);
        }
        if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
                fprintf(stderr, "Not Primary Owner (%d)\n", ret);
                return NULL;
        }

        if (!dbus_connection_set_watch_functions(bus, _addWatchFunction,
                     _removeWatchFunction, NULL, NULL, NULL)) {
                fprintf(stderr,"dbus_connection_set_watch_functions failed\n");
                return NULL;
        }

        if (!dbus_connection_add_filter(bus, DB_FilterDbusFunctionMessage, engine, NULL))
        {
                printf("Failed to register signal handler callback/n");
                return NULL;
        }

        dbus_bus_add_match(bus, "type='signal'", NULL);
        dbus_bus_add_match(bus, "type='method_call'", NULL);

	DEBUG0("registered %s \n", interface);

        return bus;
}

static const char *instrospect_header = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
        "<node>\n"
        "<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
        "  <method name=\"Introspect\">\n"
        "    <arg name=\"xml_data\" direction=\"out\" type=\"s\"/>\n"
        "  </method>\n"
        "</interface>\n"
        "<interface name=\"org.freedesktop.DBus.Properties\">\n"
        "  <method name=\"Get\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
        "  </method>\n"
        "  <method name=\"Set\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"value\" direction=\"in\" type=\"v\"/>\n  </method>\n"
        "  <method name=\"GetAll\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"props\" direction=\"out\" type=\"a{sv}\"/>\n"
        "  </method>\n"
        "</interface>\n"
;

void PODS_Method_Instrospect(DBusConnection *conn,DBusMessage *msg, void *data) {
        DBusMessageIter iter;
        DBusMessage *reply = NULL;
        ST_Callback *current = NULL;
        ST_Interface *interfaces = NULL;
	GList *item = polybus.interfaces;
        GString* xml_data;
        int i,j,offset;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init_append (reply, &iter);

        /* xml header instropection format */
        xml_data = g_string_new (instrospect_header);

        /* Now for every interface we publish their methods, signals and properties */
	
	while(item!= NULL) {	
                interfaces = (ST_Interface*)item->data;
                //interfaces = (ST_Interface*)&ST_PublicInterfaces[i];

                /* Now the methods supported by the interface of the agent */
                //printf("(%d)Checking interface '%s' (methods:%d)(signals:%d)props(%d)\n",i,
                //      interfaces->name,interfaces->total_methods,interfaces->total_signals,interfaces->total_properties);
                g_string_append_printf (xml_data," \n<interface name=\"%s\">\n  ",interfaces->name);

                current = &interfaces->methods[0];
                for (j = 0; j<interfaces->total_methods;j++) {

                        g_string_append_printf(xml_data,"<method name=\"%s\">\n",current[j].name);

                        /* adding the format parameters */
                        if(current[j].in != NULL) {
                                g_string_append_printf(xml_data,"    <arg name=\"%s\" type=\"%s\" direction=\"in\"/>\n",
                                        current[j].in,current[j].in);
                        }
                        if(current[j].out != NULL) {
                                g_string_append_printf(xml_data,"    <arg name=\"result\" type=\"%s\" direction=\"out\"/>\n",
                                       current[j].out);
                        }

                        g_string_append(xml_data,"  </method>\n");
                }

                /* now check for signals */
                /* TODO not implemented jet */

                /* now check for properties */
                current = &interfaces->properties[0];
                for (j = 0;j<interfaces->total_properties;j++) {
                        char *access = "read";
                        char *type = "";
                        g_string_append_printf(xml_data,"  <property name=\"%s\" ",
                               current[j].name);
                        if(current[j].in == NULL)
                                access = "read";
                        else
                                access = "readwrite";
                        type = current[j].out;
                        g_string_append_printf(xml_data,"type=\"%s\" access=\"%s\"/>\n",type,access);
                }

                g_string_append(xml_data,"</interface>\n");
		item = g_list_next(item);
        }
        g_string_append(xml_data, "</node>\n");
//      printf("%s",xml_data->str);
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &xml_data->str);
        g_string_free (xml_data, TRUE);

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
        return;

}

/**
 * PODS_SendSuspiciousSegment - The filter engine sends the suspicious tcp segment to the detection engine process.
 *
 * @param conn the DBusConnection
 * @param objectname 
 * @param interfacename
 * @param name
 * @param ptr
 * @param length
 * @param hash
 * @param seq
 *
 */
void PODS_SendSuspiciousSegment(DBusConnection *conn,char *objectname,char *interfacename,char *name,unsigned char *ptr,int length,
	unsigned long hash, u_int32_t seq) {
	DBusMessage *msg;
	DBusMessageIter iter,dataIter;
	dbus_int32_t len = length;
	dbus_uint32_t dhash = hash;
	dbus_uint32_t dseq = seq;

   	msg = dbus_message_new_signal(objectname,interfacename,name);
   	if (msg == NULL) {
      		fprintf(stderr, "Message Null\n");
      		exit(1);
   	}

        /* Sends a full segment to the detector
         * 
         * 1 - arrray with the buffer and its lenght.
         * 2 - the hash of the connection flow.
         * 3 - the sequence number.
         */
        dbus_message_iter_init_append(msg,&iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &dataIter);
        dbus_message_iter_append_fixed_array(&dataIter, DBUS_TYPE_BYTE, &ptr, len);
        dbus_message_iter_close_container(&iter, &dataIter);

        dbus_message_iter_append_basic(&iter,DBUS_TYPE_UINT32,&dhash);
        dbus_message_iter_append_basic(&iter,DBUS_TYPE_UINT32,&dseq);

   	if (!dbus_connection_send(conn, msg, NULL)) {
      		fprintf(stderr, "Out Of Memory!\n");
      		exit(1);
		
   	}
   	dbus_connection_flush(conn);
   	dbus_message_unref(msg);
	return;
}

/**
 * PODS_SendSegmentVeredict - The filter engine, or the detection engine
 *  sends the final verification to the protection engine.
 *
 * @param conn the DBusConnection
 * @param objectname 
 * @param interfacename
 * @param name
 * @param hash  
 * @param seq
 * @param veredict 
 *
 */

void PODS_SendVerifiedSegment(DBusConnection *conn,char *objectname,char *interfacename, char *name,
	unsigned long hash, u_int32_t seq,int veredict) {
        DBusMessage *msg;
        DBusMessageIter args;
	dbus_uint32_t dseq = seq;
	dbus_uint32_t dhash = hash;
	dbus_int32_t dveredict = veredict;

        msg = dbus_message_new_signal(objectname,interfacename,name);
        if (msg == NULL) {
                fprintf(stderr, "Message Null\n");
                exit(1);
        }

        dbus_message_iter_init_append(msg, &args);
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &dseq)) {
                fprintf(stderr, "Out Of Memory!\n");
                exit(1);
        }
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &hash)) {
                fprintf(stderr, "Out Of Memory!\n");
                exit(1);
        }
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &dveredict)) {
                fprintf(stderr, "Out Of Memory!\n");
                exit(1);
        }

        if (!dbus_connection_send(conn, msg, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                exit(1);

        }
        dbus_connection_flush(conn);
        dbus_message_unref(msg);
        return;




}
