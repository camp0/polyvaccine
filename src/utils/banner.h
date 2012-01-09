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
#ifndef _BANNER_H_
#define _BANNER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

static char *version_banner =  
"GNU " PACKAGE " " PACKAGE_VERSION "\n"
"Copyright 2009 Free Software Foundation, Inc.\n"
"This program is free software; you may redistribute it under the terms of\n"
"the GNU General Public License version 2 or (at your option) any later version.\n"
"This program has absolutely no warranty.\n";

static char *bugs_banner = 
"Report bugs to <" PACKAGE_BUGREPORT ">.\n";

#endif
