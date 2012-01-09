__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Utility for load and unload the httpcache over dbus
#
import getopt
import sys
import MySQLdb
import dbus

def createDatabaseModel():

	conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")
	
        c = conn.cursor()
        q = "drop table IF EXISTS `httpcache`"

        try:
                c.execute(q)
                q = """ CREATE TABLE  `httpcache` (
                        `id` int(10) unsigned NOT NULL auto_increment,
                        `value` varchar(2048) NOT NULL,
                        `type` int(10) unsigned NOT NULL,
                        PRIMARY KEY  (`id`)
                        ) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;"""

                c.execute(q)
        except Exception,e:
                print e
                raise e
	c.close()
	conn.close()


def showPvfeHttpCache(i):
	
	cache = i.GetCacheHeaders()
	print "Http cache headers"
	for h in cache:
		print h
	print "Http cache parameters"
	cache = i.GetCacheParameters()
	for h in cache:
		print h

def insertPvfeHttpCache(i,update=False):
        conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")

        c = conn.cursor()
	if(update==False):
	        q = "delete from httpcache"
		c.execute(q)

	cache = i.GetCacheHeaders()
	for h in cache:
		sql = "insert into httpcache (value,type)values('%s',0)" % h
		c.execute(sql)
        cache = i.GetCacheParameters()
        for h in cache:
                sql = "insert into httpcache (value,type)values('%s',1)" % h
                c.execute(sql)

	conn.commit()		
        c.close()
        conn.close()

def insertHttpCachePvfe(i):
        conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")

        c = conn.cursor()
	sql = "select value from httpcache where type = 0"
	c.execute(sql)
	res = c.fetchall()
	for h in res:
		i.AddCacheHeader(h[0])

	sql = "select value from httpcache where type = 1"
	c.execute(sql)
	res = c.fetchall()
	for h in res:
		i.AddCacheParameter(h[0])

        c.close()
        conn.close()


def usage():
        print "Use: python %s [OPTIONS]" %sys.argv[0]
        print "Options"
        print "\t-c                        Create database model."
        print "\t-l                        Load the database on the pvfe."
        print "\t-i                        Inserts the httpcache of the pvfe on database."
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

        try:
                opts, args = getopt.getopt(sys.argv[1:], "vclisu")
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
                else:
                        assert False, "unhandled option"

	return create_database_model,load_database_model,insert_database_model,show_httpcache \
	update_database_model,verbose 


	
if __name__ == '__main__':
	
	create_database_model,load_database_model,insert_database_model,show_httpcache,\
	update_database_model,verbose = parseArguments()

	if(create_database_model):
		createDatabaseModel()
	elif(insert_database_model):
		bus = dbus.SessionBus()
		s = bus.get_object('polyvaccine.engine', '/polyvaccine/engine')
		d = dbus.Interface(s,dbus_interface='polyvaccine.engine.httpcache')
		insertPvfeHttpCache(d)
	elif(load_database_model):
		bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.engine', '/polyvaccine/engine')
                d = dbus.Interface(s,dbus_interface='polyvaccine.engine.httpcache')
                insertHttpCachePvfe(d)
	else:		
		bus = dbus.SessionBus()
		s = bus.get_object('polyvaccine.engine', '/polyvaccine/engine')
		d = dbus.Interface(s,dbus_interface='polyvaccine.engine.httpcache')
		showPvfeHttpCache(d)

	sys.exit(0)	
