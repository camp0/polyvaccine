AUTOMAKE_OPTIONS = gnu

AM_CPPFLAGS =      -I../utils/ \
		-I../bus/ \
		`pkg-config --cflags glib-2.0 dbus-1 libnetfilter_queue` 

noinst_HEADERS =	polyprotector.h nfpacket.h flow.h nfpacketpool.h

pvpe_SOURCES =  main.c	polyprotector.c privatecallbacks.c nfpacket.c nfpacketpool.c ../core/system.c ../core/authorized.c 
pvpe_LDADD = ../bus/libpolybus.la $(DEPS_LIBS) 
pvpe_LDFLAGS = $(DEPS_LIBS) ../bus/libpolybus.la `pkg-config --libs libnetfilter_queue glib-2.0 dbus-1`

if HAVE_PROTECTION_ENGINE

bin_PROGRAMS = pvpe 

endif

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build $(srcdir)/.deps $(srcdir)/.libs`

