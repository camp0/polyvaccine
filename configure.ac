AC_INIT([polyvaccine],[0.6],[luis.camp0.2009@gmail.com],[],[])
AM_INIT_AUTOMAKE([subdir-objects])
AM_PROG_LIBTOOL

AC_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/ax_python_module.m4])
m4_include([m4/ax_pkg_swig.m4])
m4_include([m4/debug.m4])

AC_PREREQ(2.59)

AC_PROG_INSTALL

AC_LANG([C])
AC_PROG_CC
#AC_PROG_CXX
AC_PROG_MAKE_SET
#AC_SUBST([AM_CFLAGS], [-Wall -fPIC -Wunused-variable])
#AC_SUBST([AM_CPPFLAGS], [-Wall -fPIC -Wunused-variable])

dnl AC_CANONICAL_HOST
AC_CANONICAL_HOST
AM_CONDITIONAL([__FREEBSD__],false)
AM_CONDITIONAL([__LINUX__],false)
case $host in
        *free*)    
    		AC_DEFINE([__FREEBSD__],[1],[FreeBSD Host])
    		AM_CONDITIONAL([__FREEBSD__],true)
            	;;
	*linux*)
		AC_DEFINE([__LINUX__],[1],[Linux Host])
    		AM_CONDITIONAL([__LINUX__],true)
		;;
esac

AM_PATH_PYTHON(2.6)

AC_PATH_PROGS([SWIG],[swig swig2.0])
if test -z "$SWIG" ; then
        enable_swig=no
else
        enable_swig=yes
        AX_PKG_SWIG(1.3.36,[] ,[AC_MSG_ERROR("Swig is required.")])
        AX_SWIG_ENABLE_CXX
        AX_SWIG_MULTI_MODULE_SUPPORT
        AX_SWIG_PYTHON
fi


dnl Checks for libraries
AC_PYTHON_MODULE(unittest)

AX_PYTHON

AC_CHECK_LIB(glib-2.0, main, ,AC_MSG_ERROR("Install glib library"),)
#AC_CHECK_HEADER([glib.h], ,[AC_MSG_ERROR("glib.h header not found.")],)
#AC_CHECK_HEADER([glib-2.0/glib.h], ,[AC_MSG_ERROR("glib.h header not found.")],)

dnl pcap 
AC_CHECK_LIB(pcap, main, ,AC_MSG_ERROR("Install pcap library"),)
AC_CHECK_HEADER(pcap.h, ,[AC_MSG_ERROR("pcap.h header not found.")],)

dnl pcap 
AC_CHECK_LIB(log4c, main, ,AC_MSG_ERROR("Install log4c library"),)
AC_CHECK_HEADER(log4c.h, ,[AC_MSG_ERROR("log4c.h header not found.")],)

SECCOMP="yes"
AC_CHECK_LIB(seccomp,main,,SECCOMP="no")
if test "$SECCOMP" = "no"; then
	echo
    	echo "   ERROR!  libseccomp library not found, go get it"
    	echo "   from http://sourceforge.net/projects/libseccomp/."
    	echo
    	exit
fi
AC_CHECK_HEADER(seccomp.h,,[AC_MSG_ERROR("seccomp.h header not found.")],)


AC_MSG_CHECKING(for perl regular expressions support)
AC_ARG_WITH(pcre, AC_HELP_STRING([--with-pcre],[Enable pcre support (default yes)]),
    [WITH_PCRE=$withval],[WITH_PCRE=yes])
AC_MSG_RESULT([$WITH_PCRE])

if test "$WITH_PCRE" != "no"; then
  AC_PATH_PROG(PCRECONFIG, pcre-config)

  if test x"$PCRECONFIG" != x; then
    PCRE_LIB=`$PCRECONFIG --libs`
    CPPFLAGS="$CPPFLAGS `$PCRECONFIG --cflags`"
    AC_DEFINE([HAVE_LIBPCRE], [1], [libpcre])
    AC_DEFINE([HAVE_PCRE_H], [1], [pcre.h])
  else
     AC_MSG_ERROR([pcre-config not found, install the pcre-devel package or build with --without-pcre])
  fi
fi

AC_SUBST(PCRE_LIB)
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ],
        [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
        )

    if test "x$pcre_jit_available" = "xyes"; then
       AC_MSG_RESULT(yes)
       AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

       AC_MSG_CHECKING(for PCRE JIT support usability)
       AC_TRY_COMPILE([ #include <pcre.h> ],
           [
           const char* regexstr = "(a|b|c|d)";
           pcre *re;
           const char *error;
           pcre_extra *extra;
           int err_offset;
           re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
           extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ],
           [ pcre_jit_works=yes ], [:]
       )
       if test "x$pcre_jit_works" != "xyes"; then
           AC_MSG_RESULT(no)
           echo
           echo "   PCRE JIT support detection worked but testing it failed"
           echo "   something odd is going on, please file a bug report."
           echo
           exit 1
       else
           AC_MSG_RESULT(yes)
       fi
    fi




#PKG_CHECK_MODULES(GLIB,[glib-2.0 >= 2.10.3],[],AC_MSG_ERROR($GLIB_PKG_ERRORS))
#PKG_CHECK_MODULES(Seccomp,libseccomp)
PKG_CHECK_MODULES(DBUS,dbus-1 )

AC_CHECK_DEBUG

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
	then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
	enable_doxygen=no
else
	enable_doxygen=yes
fi
AM_CONDITIONAL([HAVE_DOXYGEN], 
[test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/doxyfile])])


#enable support for NFQUEUE
AM_CONDITIONAL([HAVE_PROTECTION_ENGINE],false)
NFQ_ENABLE="no"
    #NFQ="no"
    AC_ARG_ENABLE(nfqueue,
           AS_HELP_STRING([--enable-nfqueue], [Enable NFQUEUE support for Protection Engine]),,[enable_nfqueue=no])
    AS_IF([test "x$enable_nfqueue" = "xyes"], [
        CFLAGS="$CFLAGS -DNFQ"

#libnfnetlink
case $host in
*-*-mingw32*)
;;
*)
    AC_ARG_WITH(libnfnetlink_includes,
            [  --with-libnfnetlink-includes=DIR  libnfnetlink include directory],
            [with_libnfnetlink_includes="$withval"],[with_libnfnetlink_includes=no])
    AC_ARG_WITH(libnfnetlink_libraries,
            [  --with-libnfnetlink-libraries=DIR    libnfnetlink library directory],
            [with_libnfnetlink_libraries="$withval"],[with_libnfnetlink_libraries="no"])

    if test "$with_libnfnetlink_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libnfnetlink_includes}"
    fi

    AC_CHECK_HEADER(libnfnetlink/libnfnetlink.h,,[AC_ERROR(libnfnetlink.h not found ...)])

    if test "$with_libnfnetlink_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libnfnetlink_libraries}"
    fi

	AM_CONDITIONAL([HAVE_PROTECTION_ENGINE],true)
    NFNL=""
    AC_CHECK_LIB(nfnetlink, nfnl_fd,, NFNL="no")

    if test "$NFNL" = "no"; then
    echo
    echo "   ERROR!  nfnetlink library not found, go get it"
    echo "   from www.netfilter.org."
    echo "   we automatically append libnetfilter_queue/ when searching"
    echo "   for headers etc. when the --with-libnfnetlink-inlcudes directive"
    echo "   is used"
    echo
    exit 
    fi
;;
esac

AC_ARG_ENABLE(valgrind,
              AS_HELP_STRING([--enable-valgrind],
                             [compile with valgrind macros to assist with debugging]),[enable_valgrind=yes],[enable_valgrind=no])

AS_IF([test "x$enable_valgrind" = "xyes"],
      [AC_CHECK_HEADERS(valgrind/memcheck.h,
                        [AC_DEFINE([USE_VALGRIND],[1], [Use Valgrind Macros])])])
#libnetfilter_queue
    AC_ARG_WITH(libnetfilter_queue_includes,
            [  --with-libnetfilter_queue-includes=DIR  libnetfilter_queue include directory],
            [with_libnetfilter_queue_includes="$withval"],[with_libnetfilter_queue_includes=no])
    AC_ARG_WITH(libnetfilter_queue_libraries,
            [  --with-libnetfilter_queue-libraries=DIR    libnetfilter_queue library directory],
            [with_libnetfilter_queue_libraries="$withval"],[with_libnetfilter_queue_libraries="no"])

    if test "$with_libnetfilter_queue_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_queue_includes}"
    fi

    AC_CHECK_HEADER(libnetfilter_queue/libnetfilter_queue.h,,[AC_ERROR(libnetfilter_queue/libnetfilter_queue.h not found ...)])

    if test "$with_libnetfilter_queue_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_queue_libraries}"
    fi

#LDFLAGS="${LDFLAGS} -lnetfilter_queue"

#    NFQ=""

case $host in
*-*-mingw32*)
    AC_CHECK_LIB(netfilter_queue, nfq_open,, NFQ="no",-lws2_32)

    AC_ARG_WITH(netfilterforwin_includes,
            [  --with-netfilterforwin-includes=DIR  netfilterforwin include directory],
            [with_netfilterforwin_includes="$withval"],[with_netfilterforwin_includes=no])

    if test "$with_netfilterforwin_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_netfilterforwin_includes}"
    else
    CPPFLAGS="${CPPFLAGS} -I../../netfilterforwin"
    fi
;;
*)
    AC_CHECK_LIB(netfilter_queue, nfq_open,, NFQ="no",)
    AC_CHECK_LIB([netfilter_queue], [nfq_set_queue_maxlen],AC_DEFINE_UNQUOTED([HAVE_NFQ_MAXLEN],[1],[Found queue max length support in netfilter_queue]) ,,[-lnfnetlink])
    AC_CHECK_LIB([netfilter_queue], [nfq_set_verdict2],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_VERDICT2],[1],[Found nfq_set_verdict2 function in netfilter_queue]) ,,[-lnfnetlink])

    # check if the argument to nfq_get_payload is signed or unsigned
    AC_MSG_CHECKING([for signed nfq_get_payload payload argument])
    STORECFLAGS="${CFLAGS}"
    CFLAGS="${CFLAGS} -Werror"
    AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM(
                [
                #include <libnetfilter_queue/libnetfilter_queue.h>
                ],
                [
                char *pktdata;
                nfq_get_payload(NULL, &pktdata);
                ])],
            [libnetfilter_queue_nfq_get_payload_signed="yes"],
            [libnetfilter_queue_nfq_get_payload_signed="no"])
    AC_MSG_RESULT($libnetfilter_queue_nfq_get_payload_signed)
    if test "x$libnetfilter_queue_nfq_get_payload_signed" = "xyes"; then
        AC_DEFINE([NFQ_GET_PAYLOAD_SIGNED], [], [For signed version of nfq_get_payload])
    fi
    CFLAGS="${STORECFLAGS}"
;;
esac

    if test "$NFQ" = "no"; then
    echo
    echo "   ERROR!  libnetfilter_queue library not found, go get it"
    echo "   from www.netfilter.org."
    echo "   we automatically append libnetfilter_queue/ when searching"
    echo "   for headers etc. when the --with-libnfq-includes directive"
    echo "   is used"
    echo
    exit 1 
	else
		NFQ_ENABLE="yes"
    fi
])

AC_ARG_ENABLE(malloc,
           AS_HELP_STRING([--enable-malloc], [Enable malloc instead the glib allocator]),[enable_malloc=yes],[enable_malloc=no])

if test "x$enable_malloc" == "xyes"; then
  AC_DEFINE([HAVE_MALLOC],[1],[Use malloc instead glib allocator])
fi

dnl IPv6 support
AC_ARG_ENABLE(ipv6,
           AS_HELP_STRING([--enable-ipv6], [Enable IPv6 support]),[enable_ipv6=yes],[enable_ipv6=no])

if test x"$enable_ipv6" == "xyes"; then
  AC_CACHE_CHECK([for IPv6 support], ac_cv_ipv6_support,
    [AC_TRY_LINK([ 	#include <sys/types.h>
				#include <sys/socket.h>
				#include <netinet/in.h>], 
				[struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0; ],
  [ac_cv_ipv6_support=yes], [ac_cv_ipv6_support=no])])

  if test "$ac_cv_ipv6_support" = yes; then
    AC_DEFINE(HAVE_IPV6,1,[Whether to enable IPv6 support])
  fi
fi

AC_OUTPUT([
Makefile
asm/Makefile
extra/Makefile
src/utils/Makefile
src/opcodes/Makefile
src/bus/Makefile
src/core/Makefile
src/detection/Makefile
src/protection/Makefile
test/Makefile
test/pcapfiles/Makefile
docs/Makefile
samples/exploits/Makefile
samples/exploits/http/Makefile
samples/exploits/sip/Makefile
])

echo "
  Polyvaccine 
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Platform................: $host
  Prefix..................: $prefix
  C preprocessor..........: $CPP
  C Compiler..............: $CC
  C preprocessor flags....: $CPPFLAGS
  C compiler flags........: $CFLAGS
  Linker flags............: $LDFLAGS 
  Extra libraries.........: $LIBS 
  Debug Build.............: $enable_debug
  Doxygen.................: $enable_doxygen
  Swig enable.............: $enable_swig
  Protection Engine.......: $NFQ_ENABLE
  IPv6 support............: $enable_ipv6
  Pcre JIT support........: $pcre_jit_available
  Valgrind support........: $enable_valgrind
  Enable malloc...........: $enable_malloc
  Seccomp support.........: $SECCOMP
"

