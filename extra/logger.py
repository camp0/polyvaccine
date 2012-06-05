__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Listen some signals of the filter engine
#
import gobject
from dbus.mainloop.glib import DBusGMainLoop
import os
import sys
import dbus
import time
import GeoIP

def inet_ntoa(number):
        l = list()
        l.append(str((number&0xff)))
        l.append(str((number>>8)&0xff))
        l.append(str((number>>16)&0xff))
        l.append(str((number>>24)&0xff))
        return '.'.join(l)

class Logger:
	def __str__(self):
		return "Logger:"

	def __init__(self):
		self.__bus = dbus.SessionBus(mainloop=DBusGMainLoop())
		self.__bus.add_signal_receiver(self.handler,dbus_interface='polyvaccine.logger')
		self.__geo = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
		self.__incidents = dict() 
		
	def handler(self,*args):
		ipuser = inet_ntoa(int(args[0]))
		country = self.__geo.country_name_by_addr(ipuser)
		print "Suspicious User",ipuser,"from",country
		if(self.__incidents.has_key(country)):
			self.__incidents[country] += 1
		else:
			self.__incidents[country] = 1
		
	def __del__(self):
		self.__bus.close()

	def stats(self):
		print "Total Incidents",self.__incidents

if __name__ == '__main__':

	l = Logger()
	loop = gobject.MainLoop()

	try:
		loop.run()
	except KeyboardInterrupt:
		l.stats()
	sys.exit(0)	
