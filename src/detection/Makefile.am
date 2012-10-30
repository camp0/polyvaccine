AUTOMAKE_OPTIONS = gnu

INCLUDES =      -I../utils/ -I../opcodes/ \
		-I../bus/ \
		`pkg-config --cflags glib-2.0 dbus-1` 

noinst_HEADERS =	examples.h examples64.h polydetector.h \
			examples64freebsd.h segment.h sandbox.h \
			sharedcontext.h

bin_PROGRAMS = pvde sendexploit test_pvde

pvde_SOURCES =  main.c polydetector.c privatecallbacks.c sharedcontext.c segment.c sandbox.c \
		../core/system.c ../core/trustoffset.c 

pvde_LDFLAGS = `pkg-config --libs libseccomp glib-2.0 dbus-1`
pvde_LDADD = ../bus/libpolybus.la 

test_pvde_SOURCES = sharedcontext.c segment.c sandbox.c test_pvde.c
test_pvde_LDADD = -lglib-2.0 -lseccomp

sendexploit_SOURCES = sendexploit.c
sendexploit_LDFLAGS = `pkg-config --libs dbus-1`

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

