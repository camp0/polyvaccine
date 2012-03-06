__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Example for manage methods and properties over dbus
#
import getopt
import sys
import dbus

def usage():
        print "Use: python %s [OPTIONS]" %sys.argv[0]
        print "Options"
        print "\t-c                        Create database model."
        print "\t-l                        Load the database on the pvfe."
        print "\t-i                        Inserts the httpcache of the pvfe on database."
        print "\t-f <file>                 Inserts the httpcache of the pvfe on database from a file."
        print "\t-u                        Updates the httpcache of the pvfe on database."
        print "\t-s                        Shows the httpcache of the pvfe."
	print "\n"
	print "\t-v                        Show verbose messages."
	print "\n"

def parseArguments():
	create_database_model = False
	load_database_model = False
	insert_database_model = False
	update_database_model = False
	show_httpcache = False
	verbose = 0
	insert_database_model_file = None 

        try:
                opts, args = getopt.getopt(sys.argv[1:], "vclisuf:")
        except getopt.GetoptError, err:
                print str(err) # will print something like "option -a not recognized"
                usage()
                sys.exit(2)
        for o, a in opts:
                if o in ("-v"):
                        verbose = verbose +1
                elif o in ("-c"):
                	create_database_model = True 
                elif o in ("-l"):
                       	load_database_model = True 
                elif o in ("-i"):
                     	insert_database_model = True 
                elif o in ("-s"):
                     	show_httpcache = True 
                elif o in ("-f"):
                   	insert_database_model_file = a 
                else:
                        assert False, "unhandled option"

	return create_database_model,load_database_model,insert_database_model,show_httpcache,update_database_model,\
	insert_database_model_file,verbose

	
if __name__ == '__main__':
	
	create_database_model,load_database_model,insert_database_model,show_httpcache,\
	update_database_model,filename,verbose = parseArguments()


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
