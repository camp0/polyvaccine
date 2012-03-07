__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Example for manage methods and properties over dbus.
#
import getopt
import sys
import dbus
	
if __name__ == '__main__':
	
	bus = dbus.SessionBus()
	try:
		proxy = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
	except:	
		print "No Filter engine available on the bus"
		sys.exit(-1)
	iface = dbus.Interface(proxy,dbus_interface='polyvaccine.filter')

	props = iface.GetProperties()
	print props	
	iface.SetProperties('SetSource',dbus.String('leches'))	
	props = iface.GetProperties()
	print props

	sys.exit(0)	
