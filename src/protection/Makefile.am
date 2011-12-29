AUTOMAKE_OPTIONS = gnu

INCLUDES =      -I../utils/ \
		-I../bus/ \
		`pkg-config --cflags glib-2.0 dbus-1 libnetfilter_queue` 

noinst_HEADERS =	polyprotector.h nfpacket.h flow.h nfpacketpool.h

bin_PROGRAMS = pvpe 

pvpe_SOURCES =  main.c	polyprotector.c privatecallbacks.c nfpacket.c nfpacketpool.c ../core/system.c 
pvpe_LDADD = ../bus/libpolybus.la $(DEPS_LIBS) 
pvpe_LDFLAGS = $(DEPS_LIBS) ../bus/libpolybus.la -lglib-2.0 -ldbus-1 `pkg-config --libs libnetfilter_queue`

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build $(srcdir)/.deps $(srcdir)/.libs`

