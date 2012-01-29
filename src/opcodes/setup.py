from distutils.core import setup, Extension

counter_module = Extension('_counter',
        sources=['counter_wrap.c', 'counter.c'],
	include_dirs = ['../utils','.'],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
        define_macros=[('DEBUG', '1')],
	)

setup (name = 'counter',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig example from docs""",
       ext_modules = [counter_module],
       py_modules = ["counter"],
       )

