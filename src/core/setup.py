import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../opcodes")
temp_includes.append("../bus")
temp_includes.append("../../.")

source_files = ['polyfilter_wrap.c', 'cache.c','polyfilter.c','flowpool.c','connection.c','forwarder.c']
source_files = source_files + ['privatecallbacks.c','packetdecoder.c','memory.c','memorypool.c','httpanalyzer.c','system.c']
source_files = source_files + ['../bus/polydbus.c','../opcodes/counter.c','authorized.c','trustoffset.c','tcpanalyzer.c']
source_files = source_files + ['userpool.c','user.c','dosanalyzer.c','pool.c','usertable.c']
source_files = source_files + ['sipanalyzer.c','graphcache.c','pathcache.c','httpsignalbalancer.c']

polyfilter_module = Extension('_polyfilter',
	sources = source_files,
	include_dirs = temp_includes,
#	library_dirs = [ '../opcodes/.libs'],
	libraries = ['glib-2.0','pcap','dbus-1','log4c'],
	define_macros=[('HAVE_LIBDBUS_1','1')],
	extra_compile_args = ["-Wunused-function"],
	)

setup (name = 'polyfilter',
       version = '0.1',
       author      = "Luis Campo Giralte",
       author_email = "luis.camp0.2009@gmail.com",
       description = "Simple wrapper for the tests of the filter engine",
       ext_modules = [polyfilter_module],
       py_modules = ["polyfilter"],
       )

