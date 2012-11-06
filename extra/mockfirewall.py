__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Listen some signals of the detection engine
#
import gobject
from dbus.mainloop.glib import DBusGMainLoop
import os
import sys
import dbus
import time

def inet_ntoa(number):
        l = list()
        l.append(str((number&0xff)))
        l.append(str((number>>8)&0xff))
        l.append(str((number>>16)&0xff))
        l.append(str((number>>24)&0xff))
        return '.'.join(l)

class MockFirewall:
	def __str__(self):
		return "MockFirewall:"

	def __init__(self):
		self.__bus = dbus.SessionBus(mainloop=DBusGMainLoop())
		self.__bus.add_signal_receiver(self.handler,dbus_interface='polyvaccine.protector')
		self.__segment_accept = 0	
		self.__segment_drop = 0
	
	def handler(self,*args):
		seq_number = int(args[0])
		flow_hash = int(args[1])
		decision = int(args[2])
		print "Droping flow ",flow_hash,"veredict:",decision
		if(decision == 0):
			self.__segment_drop = self.__segment_drop + 1
		else:
			self.__segment_accept = self.__segment_accept + 1
		
	def __del__(self):
		self.__bus.close()

	def stats(self):
		print "Total accepted",self.__segment_accept
		print "Total drops",self.__segment_drop

if __name__ == '__main__':

	l = MockFirewall()
	loop = gobject.MainLoop()

	try:
		loop.run()
	except KeyboardInterrupt:
		l.stats()
	sys.exit(0)	
