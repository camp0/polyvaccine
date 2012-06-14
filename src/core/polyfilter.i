%module polyfilter

%{
#include "pool.h"
#include "cache.h"
#include "graphcache.h"
#include "pathcache.h"
#include "flowpool.h"
#include "userpool.h"
#include "usertable.h"
#include "user.h"
#include "packetcontext.h"
#include "memorypool.h"
#include "memory.h"
#include "genericflow.h"
#include "polyfilter.h"
%}

%apply unsigned char * { gpointer }
%apply unsigned int { uint32_t }
%apply unsigned int { u_int32_t }
%apply int { int32_t }
%apply unsigned short { uint16_t }
%apply unsigned long long { uint64_t }
%apply char * { unsigned char*}
%apply unsigned int { time_t }

#define __attribute__(x)
%include "pool.h"
%include "cache.h"
%include "graphcache.h"
%include "pathcache.h"
%include "flowpool.h"
%include "memorypool.h"
%include "userpool.h"
%include "usertable.h"
%include "user.h"
%include "memory.h"
%include "packetcontext.h"
%include "genericflow.h"
%include "polyfilter.h"
