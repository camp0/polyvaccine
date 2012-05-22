import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags libpcre").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../../.")

counter_module = Extension('_counter',
        sources=['counter_wrap.c', 'counter.c'],
	include_dirs = temp_includes,
	libraries = ['pcre'],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
        define_macros=[('DEBUG', '1'),('HAVE_CONFIG_H','1')],
	)

setup (name = 'counter',
       version = '0.1',
       author      = "Luis Campo Giralte",
       description = """Simple wrapper for the opcode counter""",
       ext_modules = [counter_module],
       py_modules = ["counter"],
       )

