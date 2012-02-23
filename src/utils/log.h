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
#ifndef _LOG_H_
#define _LOG_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <log4c.h>

#ifndef POLYLOG_CATEGORY_NAME
#define POLYLOG_CATEGORY_NAME "root"
#endif

#define MSG(priority,msg) POLG_Msg(POLYLOG_CATEGORY_NAME,priority,msg)
#define LOG(priority,msg,args...) POLG_Log(POLYLOG_CATEGORY_NAME,priority,msg, ##args)

#ifdef HAVE_LIBLOG4C 
#define POLYLOG_PRIORITY_INFO LOG4C_PRIORITY_INFO
#define POLYLOG_PRIORITY_ALERT LOG4C_PRIORITY_ALERT
#define POLYLOG_PRIORITY_ERROR LOG4C_PRIORITY_ERROR
#define POLYLOG_PRIORITY_WARN  LOG4C_PRIORITY_WARN
#define POLYLOG_PRIORITY_NOTICE  LOG4C_PRIORITY_NOTICE
#define POLYLOG_PRIORITY_DEBUG LOG4C_PRIORITY_DEBUG
#define POLYLOG_PRIORITY_TRACE LOG4C_PRIORITY_TRACE
#else
#define POLYLOG_PRIORITY_INFO 0 
#define POLYLOG_PRIORITY_ERROR 1
#define POLYLOG_PRIORITY_WARN  2
#define POLYLOG_PRIORITY_NOTICE  3
#define POLYLOG_PRIORITY_DEBUG 4
#define POLYLOG_PRIORITY_TRACE 5
#define POLYLOG_PRIORITY_ALERT 6
#endif

static LOG4C_INLINE int POLG_Init(){
#ifdef HAVE_LIBLOG4C 
        return(log4c_init());
#else
        return 0;
#endif
}

static LOG4C_INLINE int POLG_Destroy(){
#ifdef HAVE_LIBLOG4C 
        return(log4c_fini());
#else
        return 0;
#endif
}

static LOG4C_INLINE void POLG_Msg(char *catName,int a_priority, char *msg){
#ifdef HAVE_LIBLOG4C 
        log4c_category_log(log4c_category_get(catName), a_priority, msg);
#else
        printf(msg);
#endif
}

static LOG4C_INLINE int POLG_SetAppender(char *catName, char *appName){
#ifdef HAVE_LIBLOG4C 
         log4c_category_set_appender(log4c_category_get(catName)
                                  ,log4c_appender_get(appName));
   return(0);
#else
  return(0);
#endif
}


static LOG4C_INLINE void POLG_Log(char *catName,int a_priority, char *a_format,...){
#ifdef HAVE_LIBLOG4C 
	log4c_category_t* a_category = log4c_category_get(catName);
	if (log4c_category_is_priority_enabled(a_category, a_priority)) {
        	va_list va;
        	va_start(va, a_format);
        	log4c_category_vlog(a_category, a_priority, a_format, va);
        	va_end(va);
	}
#else
  	va_list va;
        va_start(va, a_format);
        vprintf(a_format, va);
        va_end(va);
#endif
}

#endif
