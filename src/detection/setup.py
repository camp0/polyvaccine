import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../opcodes")
temp_includes.append("../bus")
temp_includes.append("../../")

source_files = [ 'polydetector_wrap.c','suspicious.c','syscalls.c','context.c','privatecallbacks.c','pvtrace.c','polydetector.c' ]
source_files = source_files + ['../bus/polydbus.c','../core/system.c','../core/trustoffset.c']

polydetector_module = Extension('_polydetector',
        sources= source_files,
	include_dirs = temp_includes,
	libraries = ['glib-2.0','dbus-1','log4c'],
	define_macros=[('HAVE_LIBDBUS_1','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
#        define_macros=[('DEBUG', '1')],
	)

setup (name = 'polydetector',
       version = '0.1',
       author      = "Luis Campo Giralte",
       description = """Simple wrapper for the detection system""",
       ext_modules = [polydetector_module],
       py_modules = ["polydetector"],
       )

