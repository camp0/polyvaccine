import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../opcodes")
temp_includes.append("../bus")
temp_includes.append("../../.")

source_files = ['polyvaccine_wrap.c', 'cache.c','polyfilter.c','flowpool.c','connection.c','forwarder.c']
source_files = source_files + ['privatecallbacks.c','packetdecoder.c','memory.c','memorypool.c','httpanalyzer.c','system.c']
source_files = source_files + ['../bus/polydbus.c','../opcodes/counter.c','authorized.c','trustoffset.c','tcpanalyzer.c']
source_files = source_files + ['sipanalyzer.c']

polyvaccine_module = Extension('_polyvaccine',
	sources = source_files,
	include_dirs = temp_includes,
#	library_dirs = [ '../opcodes/.libs'],
	libraries = ['glib-2.0','pcap','dbus-1','log4c'],
	define_macros=[('HAVE_LIBDBUS_1','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('PACKAGE','\"test\"'),('PCRE_HAVE_JIT','0'),('__LINUX__','1'),('PACKAGE_BUGREPORT','test')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
#        define_macros=[('DEBUG', '1')],
	)

setup (name = 'polyvaccine',
       version = '0.1',
       author      = "Luis Campo Giralte",
       description = """Simple wrapper for the filter engine""",
       ext_modules = [polyvaccine_module],
       py_modules = ["polyvaccine"],
       )

