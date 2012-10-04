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

#ifndef _SEGMENT_H_
#define _SEGMENT_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/mman.h>
#include <stdio.h>

#ifdef __LINUX__
enum {
	SEGMENT_EXECUTABLE = MAP_EXECUTABLE,
	SEGMENT_ANONYMOUS =MAP_ANONYMOUS
}segment_types;

#endif
#ifdef __FREEBSD__
enum {
	SEGMENT_EXECUTABLE = PROT_EXEC,
	SEGMENT_ANONYMOUS = MAP_ANON
}segment_types;

#endif

struct ST_ExecutableSegment {
	int registers_size;
	int virtualeip;
        void *original_segment; 	// Original segment, the http header with no modifications
        void *segment_with_opcodes; 	// original segment but with the opcodes modifications
        void *executable_segment; 	// a copy of the segment_with_opcodes but executable;
        int original_segment_size; 	// sizeof (original_segment)
        int executable_segment_size; 	// sizeof (segment_with_opcodes) and sizeof (executable_segment)
};
typedef struct ST_ExecutableSegment ST_ExecutableSegment;

ST_ExecutableSegment *EXSG_InitExecutableSegment(void);
void EXSG_PrepareExecutableSegment(ST_ExecutableSegment *sg,char *buffer,int size);
void EXSG_DestroyExecutableSegment(ST_ExecutableSegment *sg);
void EXSG_ExecuteExecutableSegment(ST_ExecutableSegment *sg);
void EXSG_IncreaseEIPOnExecutableSegment(ST_ExecutableSegment *sg);
void EXSG_PrintExecutableSegment(ST_ExecutableSegment *sg);

#endif
