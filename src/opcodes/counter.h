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

#ifndef _COUNTER_H_
#define _COUNTER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <pcre.h>
#include "opcodes.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#include "debug.h"

#define OVECCOUNT 30
#define REGEX_BUFFER 1024 * 32

struct ST_OpcodeCounter{
	char regular_expresion[REGEX_BUFFER];
	int ovector[OVECCOUNT];
	int32_t total_process;
        int32_t total_matchs;
	pcre *opcode_regex;
	pcre_extra *opcode_regex_study;
	char *errstr;
};
typedef struct ST_OpcodeCounter ST_OpcodeCounter;

void COSU_Init(void);
int COSU_CheckSuspiciousOpcodes(char *data,int datasize);
//int COSU_CheckSuspiciousOpcodes2(char *data,int datasize) __attribute__ ((deprecated));
void COSU_Destroy(void);
void COSU_Stats(void);

#endif
