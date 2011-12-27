import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags glib-2.0").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../opcodes")

source_files = [ 'polydetector_wrap.c','suspicious.c','syscalls.c','context.c' ]

polydetector_module = Extension('_polydetector',
        sources= source_files,
	include_dirs = temp_includes,
	libraries = ['glib-2.0'],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
#        define_macros=[('DEBUG', '1')],
	)

setup (name = 'polydetector',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig example from docs""",
       ext_modules = [polydetector_module],
       py_modules = ["polydetector"],
       )

