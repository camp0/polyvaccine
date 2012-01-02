AUTOMAKE_OPTIONS = gnu
BUILT_SOURCES = $(srcdir)/counter_wrap.c

lib_LTLIBRARIES = libopcodes.la

INCLUDES =	-I../utils/

libopcodes_la_SOURCES =	counter.c

noinst_HEADERS =	indirect.h jump.h counter.h opcodes.h

libopcodes_la_LDFLAGS = -version-info 0:0:0 
libopcodes_la_CPPFLAGS = -I$(PYTHON_CPPFLAGS)

bin_PROGRAMS = test

test_SOURCES = main.c 
test_LDADD = -lopcodes

CLEANFILES = $(srcdir)/counter_wrap.c *.pyc counter.py

PYTHON_INCLUDES = -I/usr/include -I../utils/

EXTRA_DIST = counter.i setup.py

MAINTAINERCLEANFILES = \
        $(srcdir)/counter_wrap.c \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

$(srcdir)/counter_wrap.c: counter.i
	$(SWIG) -python counter.i
	$(PYTHON) setup.py build_ext --inplace 
