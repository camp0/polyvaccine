__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Injects the traces of all directory to the pvfe in order
# to verify the resisiency of the process. Or just for fun :D
#
import os
import getopt
import sys
import dbus
import time

class Bar:
	def __init__(self):
		self.prev = '\\'
		self.curr = '|' 

	def __next(self):
		if(self.prev == '|')and(self.curr=='//'):
			self.prev = self.curr
			self.curr = '-'
			return
		if(self.prev == '//')and(self.curr=='-'):
			self.prev = self.curr
			self.curr = '\\'
			return
		if(self.prev == '-')and(self.curr=='\\'):
			self.prev = self.curr
			self.curr = '|'
			return
		if(self.prev == '\\')and(self.curr=='|'):
			self.prev = self.curr
			self.curr = '/'
			return
		if(self.prev == '|')and(self.curr=='/'):
			self.prev = self.curr
			self.curr = '-'
			return
		if(self.prev == '/')and(self.curr=='-'):
			self.prev = self.curr
			self.curr = '\\'
			return
		if(self.prev == '-')and(self.curr=='\\-'):
			self.prev = self.curr
			self.curr = '|'
			return
			

	def getState(self):
		self.__next()
		return self.curr

def usage():
        print "Use: python %s [OPTIONS]" %sys.argv[0]
        print "Options"
        print "\t-d <directory>            Directory with the pcapfiles."
	print "\n"
	print "\t-v                        Show verbose messages."
	print "\n"

def parseArguments():
	verbose = 0
	directory = None	

        try:
                opts, args = getopt.getopt(sys.argv[1:], "vd:")
        except getopt.GetoptError, err:
                print str(err) # will print something like "option -a not recognized"
                usage()
                sys.exit(2)
        for o, a in opts:
                if o in ("-v"):
                        verbose = verbose +1
                elif o in ("-d"):
                	directory = a	
                else:
                        assert False, "unhandled option"

	if(directory == None):
		usage()
		sys.exit(-1)

	return directory, verbose

	
if __name__ == '__main__':

	directory, verbose = parseArguments()
	
	bus = dbus.SessionBus()
	try:
		proxy = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
	except:	
		print "No Filter engine available on the bus"
		sys.exit(-1)
	iface = dbus.Interface(proxy,dbus_interface='polyvaccine.filter')

	listing = os.listdir(directory)
	b = Bar()
	for infile in listing:
		source = directory + "/" + infile
		iface.Stop()
		iface.SetSource(source)
		iface.Start()
		if(verbose>0):
			print "Testing trace",source
		i = 0
		while True:
			state = "none"
			sys.stdout.write("%s" % b.getState())
			#sys.stdout.flush()
			time.sleep(0.5)
			sys.stdout.write('\b')
			sys.stdout.flush()
			if((i % 10) == 0):
				state = iface.GetProperty("State")
				if(verbose>0):
					print "Checking pvfe state",state
			i = i +1	
			if ("stop" in state):
				break
	

	sys.exit(0)	
