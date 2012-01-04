AUTOMAKE_OPTIONS = gnu

lib_LTLIBRARIES = libpolyvaccine.la

INCLUDES =      -I../opcodes/ \
		`pkg-config --cflags dbus-1 glib-2.0` \
                -I../utils/ \
		-I../bus/ 

BUILT_SOURCES = $(srcdir)/polyvaccine_wrap.c

libpolyvaccine_la_SOURCES =	system.c memory.c memorypool.c privatecallbacks.c flowpool.c \
				connection.c packetdecoder.c authorized.c \
				httpanalyzer.c httpcache.c polyengine.c 

noinst_HEADERS =	httpvalues.h flowpool.h connection.h httpcache.h polyengine.h \
			packetdecoder.h packetcontext.h httpflow.h authorized.h privatecallbacks.h \
			httpanalyzer.h memory.h memorypool.h system.h 

libpolyvaccine_la_LIBADD = ../opcodes/libopcodes.la ../bus/libpolybus.la $(DEPS_LIBS) 
libpolyvaccine_la_LDFLAGS = -version-info 0:0:0 $(DEPS_LIBS) `pkg-config --libs glib-2.0 dbus-1`
libpolyvaccine_la_CPPFLAGS = -I$(PYTHON_CPPFLAGS) $(DEPS_CFLAGS)

PYTHON_INCLUDES = -I/usr/include -I. -I.. -I../.. "`pkg-config --cflags glib-2.0 dbus-1`" 

bin_PROGRAMS = pvfe 

pvfe_SOURCES = main.c 
pvfe_LDFLAGS = $(DEPS_LIBS) -lpolyvaccine -lpcap 
pvfe_LDADD = -lpolyvaccine $(DEPS_LIBS)

EXTRA_DIST = polyvaccine.i setup.py

CLEANFILES = $(srcdir)/polyvaccine_wrap.c $(srcdir)/_polyvaccine.so *.pyc polyvaccine.py 

MAINTAINERCLEANFILES = \
	$(srcdir)/polyvaccine_wrap.c \
	$(srcdir)/Makefile.in \
	`rm -rf $(srcdir)/build `

$(srcdir)/polyvaccine_wrap.c: polyvaccine.i
	$(SWIG) -python polyvaccine.i
	$(PYTHON) setup.py build_ext --inplace -DHAVE_CONFIG_H

