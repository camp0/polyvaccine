__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Utility for load and unload the graphcache over dbus
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
        	q = "drop table IF EXISTS `graphcache`"
                c.execute(q)
                q = """ CREATE TABLE  `graphcache` (
                        `id` int(10) unsigned NOT NULL auto_increment,
                        `id_uri1` int(10) NOT NULL,
                        `id_uri2` int(10)) NOT NULL,
                        `cost` int(10) unsigned NOT NULL,
                        PRIMARY KEY  (`id`)
                        ) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;"""
                c.execute(q)
        except Exception,e:
                print e
                raise e
	c.close()
	conn.close()


def getSrcNodes(filename):
	nodes = dict()

	f = open(filename,'r')
	lines = f.readlines()

	for line in lines:
		token = "UriSrc("
		if(token in line):
			value = line[len(token)+2:]
			value = value[:len(value)-2]
			nodes[value] = dict()	

	f.close()
	return nodes


def insertFileOnDatabase(filename):
	errors = 0
	inserts = 0
	f = open(filename)
	lines = f.readlines()

	conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")
        c = conn.cursor()

	for l in lines:
		if(("Header(" in l)and(")matchs" in l)):
			i = l.find("Header(")
			j = l.find(")matchs")
			value = l[i+7:j]
			sql = "insert into httpcache (value,type)values('%s',0)" % value
			try:
				c.execute(sql)
				inserts = inserts +1
			except:
				errors = errors +1	
		if(("Parameter(" in l)and(")matchs" in l)):
			i = l.find("Parameter(")
			j = l.find(")matchs")
			value = l[i+10:j]
			sql = "insert into httpcache (value,type)values('%s',1)" % value
			try:
				c.execute(sql)	
				inserts = inserts +1
			except:
				errors = errors +1	

	conn.commit()		
	f.close()
	c.close()
	conn.close()
	print "Total inserts %d errors %d\n" %(inserts,errors)

def insertPvfeHttpCache(i,update=False):
        conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")

        c = conn.cursor()
	if(update==False):
	        q = "delete from httpcache"
		c.execute(q)

	cache = i.GetCacheHeaders()
	if(cache != None):
		for h in cache:
			sql = "insert into httpcache (value,type)values('%s',0)" % h
			c.execute(sql)
        cache = i.GetCacheParameters()
	if(cache != None):
        	for h in cache:
                	sql = "insert into httpcache (value,type)values('%s',1)" % h
                	c.execute(sql)

	conn.commit()		
        c.close()
        conn.close()

def insertHttpCachePvfe(i):
        conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")
	loads = 0
	errors = 0

        c = conn.cursor()
	sql = "select value from httpcache where type = 0"
	c.execute(sql)
	res = c.fetchall()
	for h in res:
		try:
			i.AddCacheHeader(h[0])
			loads = loads + 1
		except:
			errors = errors + 1
	sql = "select value from httpcache where type = 1"
	c.execute(sql)
	res = c.fetchall()
	for h in res:
		try:
			i.AddCacheParameter(h[0])
			loads = loads + 1
		except:
			errors = errors + 1

        c.close()
        conn.close()
	print "Loaded %d errrors %d\n" %(loads,errors)

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


	a = getSrcNodes("pepe.dat")
	print a
	sys.exit(0)

	
	create_database_model,load_database_model,insert_database_model,show_httpcache,\
	update_database_model,filename,verbose = parseArguments()

	if(filename):
		insertFileOnDatabase(filename)
		sys.exit(0)

	if(create_database_model):
		createDatabaseModel()
	elif(insert_database_model):
		bus = dbus.SessionBus()
		try:
			s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
		except:	
			print "No Filter engine available on the bus"
			sys.exit(-1)
		d = dbus.Interface(s,dbus_interface='polyvaccine.filter.httpcache')
		insertPvfeHttpCache(d)
	elif(load_database_model):
		bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
                d = dbus.Interface(s,dbus_interface='polyvaccine.filter.httpcache')
                insertHttpCachePvfe(d)
	else:		
		bus = dbus.SessionBus()
		try:
			s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
		except:
			print "No Filter engine available on the bus"
			sys.exit(-1)
		d = dbus.Interface(s,dbus_interface='polyvaccine.filter.httpcache')
		showPvfeHttpCache(d)

	sys.exit(0)	
