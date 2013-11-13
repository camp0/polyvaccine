AUTOMAKE_OPTIONS = gnu

AM_CPPFLAGS =      -I../opcodes/ \
		`pkg-config --cflags dbus-1 glib-2.0` \
                -I../utils/ \
		-I../bus/ 

noinst_HEADERS =	examples.h examples64.h polydetector.h \
			examples64freebsd.h segment.h sandbox.h \
			sharedcontext.h

bin_PROGRAMS = pvde 

pvde_SOURCES =  main.c polydetector.c privatecallbacks.c sharedcontext.c segment.c sandbox.c \
		../core/system.c ../core/trustoffset.c 

pvde_LDFLAGS = `pkg-config --libs libseccomp glib-2.0 dbus-1`
pvde_LDADD = $(DBUS_LIBS) $(top_builddir)/src/bus/libpolybus.la 
#pvde_LDFLAGS = $(AM_CPPFLAGS) 

check_PROGRAMS = sendexploit test_pvde

test_pvde_SOURCES = sharedcontext.c segment.c sandbox.c test_pvde.c
test_pvde_LDFLAGS = `pkg-config --libs glib-2.0 libseccomp`

sendexploit_SOURCES = sendexploit.c
sendexploit_LDFLAGS = $(top_builddir)/src/bus/libpolybus.la `pkg-config --libs dbus-1`

BUILT_SOURCES = $(srcdir)/polydetector_wrap.c

EXTRA_DIST = polydetector.i setup.py log4crc

CLEANFILES = $(srcdir)/polydetector_wrap.c $(srcdir)/_polydetector.so *.pyc polydetector.py

MAINTAINERCLEANFILES = \
        $(srcdir)/polydetector_wrap.c \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

$(srcdir)/polydetector_wrap.c: polydetector.i
	$(SWIG) -python polydetector.i
	$(PYTHON) setup.py build_ext --inplace -DHAVE_CONFIG_H 

