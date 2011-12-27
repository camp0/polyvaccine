AUTOMAKE_OPTIONS = gnu

lib_LTLIBRARIES = libpolybus.la

INCLUDES =      -I../opcodes/ \
		`pkg-config --cflags dbus-1 glib-2.0` \
                -I../utils/ 

libpolybus_la_SOURCES =	polydbus.c 
noinst_HEADERS =	polydbus.h 

libpolybus_la_LIBADD = $(DEPS_LIBS)
libpolybus_la_LDFLAGS = -version-info 0:0:0 $(DEPS_LIBS) `pkg-config --libs glib-2.0 dbus-1` 
libpolybus_la_CPPFLAGS = $(DEPS_CFLAGS)

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile.in 

