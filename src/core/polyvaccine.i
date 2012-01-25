%module polyvaccine 

%{
#include "cache.h"
#include "flowpool.h"
#include "packetcontext.h"
#include "memorypool.h"
#include "memory.h"
#include "httpflow.h"
#include "polyengine.h"
%}

%apply unsigned int { uint32_t }
%apply int { int32_t }
%apply unsigned short { uint16_t }
%apply unsigned long long { uint64_t }
%apply char * { unsigned char*}
%apply unsigned int { time_t }

%include "cache.h"
%include "flowpool.h"
%include "memorypool.h"
%include "memory.h"
%include "packetcontext.h"
%include "httpflow.h"
%include "polyengine.h"
