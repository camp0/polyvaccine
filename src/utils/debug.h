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
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define __DEBUG(a...)	do { \
	fprintf(stdout, "DEBUG:%s:%d:", __FILE__, __LINE__); \
	fprintf(stdout, a); \
} while (0)

#define __INFOMSG(a...) do { \
        fprintf(stdout, "INFO:"); \
        fprintf(stdout, a); \
} while (0)

#define __WARNING(a...) do { \
        fprintf(stdout, "WARNING:"); \
        fprintf(stdout, a); \
} while (0)


#define INFOMSG __INFOMSG
#define WARNING __WARNING

#ifdef DEBUG
#define DEBUG0 __DEBUG
#else
#define DEBUG0(a...)
#endif

#define DEBUG1(a...) 
//#define DEBUG1 __DEBUG
#define DEBUG2(a...)
//#define DEBUG2 __DEBUG

#endif
