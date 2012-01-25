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

#ifndef _TRUSTOFFSET_H_
#define _TRUSTOFFSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "debug.h"

#define MAX_OFFSETS_ALLOCATED 8 

struct ST_TrustOffsets {
	int offsets_start[MAX_OFFSETS_ALLOCATED];
	int offsets_end[MAX_OFFSETS_ALLOCATED];
	int index;
};

typedef struct ST_TrustOffsets ST_TrustOffsets;

ST_TrustOffsets *TROF_Init(void);
void TROF_Destroy(ST_TrustOffsets *t);
void TROF_Reset(ST_TrustOffsets *t);
void TROF_AddTrustOffset(ST_TrustOffsets *t, int start, int end);
int *TROF_GetStartOffsets(ST_TrustOffsets *t);
int *TROF_GetEndOffsets(ST_TrustOffsets *t);
void TROF_SetStartOffsets(ST_TrustOffsets *t,int *s);
void TROF_SetEndOffsets(ST_TrustOffsets *t, int *e);
#endif
