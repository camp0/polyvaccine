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

#ifndef _INTERFACES_H_
#define _INTERFACES_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define POLYVACCINE "polyvaccine"

/* Dbus names for the filter engine */
#define POLYVACCINE_FILTER_OBJECT "/" POLYVACCINE "/filter"
#define POLYVACCINE_BUS POLYVACCINE ".bus"

#define POLYVACCINE_FILTER_INTERFACE POLYVACCINE ".filter"
#define POLYVACCINE_FILTER_HTTP_INTERFACE POLYVACCINE_FILTER_INTERFACE ".http"
#define POLYVACCINE_FILTER_SIP_INTERFACE POLYVACCINE_FILTER_INTERFACE ".sip"
#define POLYVACCINE_FILTER_TCP_INTERFACE POLYVACCINE_FILTER_INTERFACE ".tcp"
#define POLYVACCINE_FILTER_FLOWPOOL_INTERFACE POLYVACCINE_FILTER_INTERFACE ".flowpool"
#define POLYVACCINE_FILTER_FORWARDER_INTERFACE POLYVACCINE_FILTER_INTERFACE ".forwarder"
#define POLYVACCINE_FILTER_HTTPCACHE_INTERFACE POLYVACCINE_FILTER_INTERFACE ".httpcache"
#define POLYVACCINE_FILTER_CONNECTION_INTERFACE POLYVACCINE_FILTER_INTERFACE ".connection"

/* Dbus names for the detection engine */
#define POLYVACCINE_DETECTION_OBJECT "/" POLYVACCINE "/detector"
#define POLYVACCINE_DETECTION_INTERFACE POLYVACCINE ".detector"

/* Dbus names for the protection engine */
#define POLYVACCINE_PROTECTOR_OBJECT "/" POLYVACCINE "/protector"
#define POLYVACCINE_PROTECTOR_INTERFACE POLYVACCINE ".protector"

#endif
