__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Get the stats of an interface 
#
import getopt
import sys
import dbus
import time

def usage():
        print "Use: python %s [OPTIONS]" %sys.argv[0]
        print "Options"
        print "\t-o <object>               Object name."
        print "\t-i <interface>            Interface name."
        print "\t-t <time>                 Refresh statistics time."
	print "\n"
	print "\t-v                        Show verbose messages."
	print "\n"

def parseArguments():
	verbose = 0
	interface = None	
	object_name = None
	refresh_time = 5

        try:
                opts, args = getopt.getopt(sys.argv[1:], "vi:t:o:")
        except getopt.GetoptError, err:
                print str(err) # will print something like "option -a not recognized"
                usage()
                sys.exit(2)
        for o, a in opts:
                if o in ("-v"):
                        verbose = verbose +1
                elif o in ("-i"):
                	interface = a	
                elif o in ("-o"):
                	object_name = a	
                elif o in ("-t"):
                	refresh_time = int(a)	
                else:
                        assert False, "unhandled option"

	if(interface == None)or(object_name == None):
		usage()
		sys.exit(-1)

	return object_name,interface,refresh_time, verbose

	
if __name__ == '__main__':

	object_name,interface, refresh_time, verbose = parseArguments()
	
	bus = dbus.SessionBus()
	base_interface = object_name.replace("/",".")[1:]
	print base_interface
	try:
		proxy = bus.get_object(base_interface, object_name)
	except:	
		print "No proxy %s on interface %s available on the bus" % (object_name,interface)
		sys.exit(-1)
	iface = dbus.Interface(proxy,dbus_interface=interface)

	properties = iface.GetProperties()
	while True:
		print "Statistics of interface '%s'" % interface
		try:
			for prop in properties:
				print '%-25s = %10d' %(prop,iface.GetProperty(prop))
		except:
			break
			pass
		time.sleep(refresh_time)

	sys.exit(0)	
