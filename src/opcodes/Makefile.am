AUTOMAKE_OPTIONS = gnu
BUILT_SOURCES = $(srcdir)/counter_wrap.c

lib_LTLIBRARIES = libopcodes.la

INCLUDES =	-I../utils/ `pkg-config --cflags libpcre` 

libopcodes_la_SOURCES =	counter.c

noinst_HEADERS =	counter.h opcodes.h

libopcodes_la_LDFLAGS = -version-info 0:0:0 `pkg-config --libs libpcre` 
libopcodes_la_CPPFLAGS = -I$(PYTHON_CPPFLAGS)

check_PROGRAMS = test

test_SOURCES = main.c
test_LDADD = $(top_builddir)/src/opcodes/libopcodes.la

CLEANFILES = $(srcdir)/counter_wrap.c *.pyc counter.py _counter.so

PYTHON_INCLUDES = -I/usr/include -I../utils/

EXTRA_DIST = counter.i setup.py

MAINTAINERCLEANFILES = \
        $(srcdir)/counter_wrap.c \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

$(srcdir)/counter_wrap.c: counter.i
	$(SWIG) -python counter.i
	$(PYTHON) setup.py build_ext --inplace
