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

#ifndef _HTTPSIGNALBALANCER_H_
#define _HTTPSIGNALBALANCER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include "polydbus.h"

struct ST_HTTPDetectorNode {
	gchar *interface;
	gchar *name;
};
typedef struct ST_HTTPDetectorNode ST_HTTPDetectorNode;

struct ST_HTTPSignalBalancer{
	GArray *detectors;
	int total_items;
	int index;
};

typedef struct ST_HTTPSignalBalancer ST_HTTPSignalBalancer;

ST_HTTPSignalBalancer *HTSB_Init(void);
void HTSB_Destroy(ST_HTTPSignalBalancer *sb);
void HTSB_AddDetectorNode(ST_HTTPSignalBalancer *sb, char *interface, char *name);
void HTSB_RemoveDetectorNode(ST_HTTPSignalBalancer *sb, char *interface, char *name);
ST_HTTPDetectorNode *HTSB_GetNext(ST_HTTPSignalBalancer *sb);

#endif
