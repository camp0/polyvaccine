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
 * Written by Luis Campo Giralte <camp0@gmail.com> 2009 
 *
 */

#ifndef _CALLBACKS_H_
#define _CALLBACKS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dbus/dbus.h>

struct ST_Callback {
        char *name;
        char *in;
        char *out;
        void (*function)(DBusConnection *c,DBusMessage *msg, void *data);
};

typedef struct ST_Callback ST_Callback;

struct ST_Interface {
        char *name;
        ST_Callback *methods;
        int total_methods;
        ST_Callback *signals;
        int total_signals;
        ST_Callback *properties;
        int total_properties;
};

typedef struct ST_Interface ST_Interface;

#define POLYVACCINE_AGENT_INTERFACE "polyvaccine.engine"
#define POLYVACCINE_AGENT_HTTP_INTERFACE POLYVACCINE_AGENT_INTERFACE ".http"
#define POLYVACCINE_AGENT_HTTPCACHE_INTERFACE POLYVACCINE_AGENT_INTERFACE ".httpcache"
#define POLYVACCINE_AGENT_CONNECTION_INTERFACE POLYVACCINE_AGENT_INTERFACE ".connection"

#endif
