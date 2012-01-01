import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../opcodes")
temp_includes.append("../bus")

source_files = ['polyvaccine_wrap.c', 'httpcache.c','polyengine.c','flowpool.c','connection.c']
source_files = source_files + ['privatecallbacks.c','packetdecoder.c','memory.c','memorypool.c','httpanalyzer.c','system.c']
source_files = source_files + ['../bus/polydbus.c','../opcodes/counter.c','authorized.c']

polyvaccine_module = Extension('_polyvaccine',
	sources = source_files,
	include_dirs = temp_includes,
#	library_dirs = [ '../opcodes/.libs'],
	libraries = ['glib-2.0','pcap','dbus-1'],
	define_macros=[('HAVE_LIBDBUS_1','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
#        define_macros=[('DEBUG', '1')],
	)

setup (name = 'polyvaccine',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig example from docs""",
       ext_modules = [polyvaccine_module],
       py_modules = ["polyvaccine"],
       )

