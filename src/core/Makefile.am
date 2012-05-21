AUTOMAKE_OPTIONS = gnu

lib_LTLIBRARIES = libpolyvaccine.la

INCLUDES =      -I../opcodes/ \
		`pkg-config --cflags dbus-1 glib-2.0 libpcre` \
                -I../utils/ \
		-I../bus/ 

BUILT_SOURCES = $(srcdir)/polyfilter_wrap.c

libpolyvaccine_la_SOURCES =	system.c memory.c pool.c memorypool.c privatecallbacks.c flowpool.c \
				connection.c packetdecoder.c authorized.c trustoffset.c tcpanalyzer.c \
				httpanalyzer.c sipanalyzer.c user.c userpool.c dosanalyzer.c cache.c \
				forwarder.c polyfilter.c pathcache.c usertable.c graphcache.c 

noinst_HEADERS =	httpvalues.h flowpool.h connection.h cache.h polyfilter.h forwarder.h tcpanalyzer.h \
			packetdecoder.h packetcontext.h genericflow.h authorized.h privatecallbacks.h \
			httpanalyzer.h memory.h memorypool.h system.h trustoffset.h sipvalues.h pathcache.h \
			sipanalyzer.h userpool.h user.h dosanalyzer.h pool.h usertable.h graphcache.h 

libpolyvaccine_la_LIBADD = ../opcodes/libopcodes.la ../bus/libpolybus.la $(DEPS_LIBS) 
libpolyvaccine_la_LDFLAGS = -version-info 0:0:0 $(DEPS_LIBS) `pkg-config --libs glib-2.0 dbus-1 libpcre`
libpolyvaccine_la_CPPFLAGS = -I$(PYTHON_CPPFLAGS) $(DEPS_CFLAGS)

PYTHON_INCLUDES = -I/usr/include -I. -I.. -I../.. "`pkg-config --cflags glib-2.0 dbus-1 libpcre`" 

bin_PROGRAMS = pvfe 

pvfe_SOURCES = main.c 
pvfe_LDFLAGS = $(DEPS_LIBS) -lpolyvaccine -lpcap 
pvfe_LDADD = -lpolyvaccine $(DEPS_LIBS)

EXTRA_DIST = polyfilter.i setup.py log4crc

CLEANFILES = $(srcdir)/polyfilter_wrap.c $(srcdir)/_polyfilter.so *.pyc polyfilter.py 

MAINTAINERCLEANFILES = \
	$(srcdir)/polyfilter_wrap.c \
	$(srcdir)/Makefile.in \
	`rm -rf $(srcdir)/build `

$(srcdir)/polyfilter_wrap.c: polyfilter.i
	$(SWIG) -python polyfilter.i
#	$(PYTHON) setup.py build_ext --inplace 
	$(PYTHON) setup.py build_ext --inplace -DHAVE_CONFIG_H

