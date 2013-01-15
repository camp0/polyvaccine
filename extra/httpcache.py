__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Utility for load and unload the httpcache over dbus
#
import redis
import optparse
import sys
import MySQLdb
import dbus
from abc import ABCMeta, abstractmethod

class DatabaseModel:
	__metaclass__ = ABCMeta

	@abstractmethod
	def createDatabaseModel(self): pass

	@abstractmethod
	def insertFileOnDatabase(self,filename): pass

	@abstractmethod
	def insertPvfeHttpCache(self,iface,update=False): pass

	@abstractmethod
	def insertHttpCachePvfe(self,iface):pass

class MysqlDatabaseModel(DatabaseModel):
 
	def createDatabaseModel(self):
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

	def insertFileOnDatabase(self,filename):
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

	def insertPvfeHttpCache(self,iface,update=False):
		conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")

		c = conn.cursor()
		if(update==False):
			q = "delete from httpcache"
			c.execute(q)

		cache = iface.GetCacheHeaders()
		if(cache != None):
			for h in cache:
				sql = "insert into httpcache (value,type)values('%s',0)" % h
				c.execute(sql)
		cache = iface.GetCacheParameters()
		if(cache != None):
			for h in cache:
				sql = "insert into httpcache (value,type)values('%s',1)" % h
				c.execute(sql)

		conn.commit()
        	c.close()
        	conn.close()


	def insertHttpCachePvfe(self,iface):
		conn = MySQLdb.connect("localhost","pvuser", "pvuser","pvdata")
		loads = 0
		errors = 0

		c = conn.cursor()
		sql = "select value from httpcache where type = 0"
		c.execute(sql)
		res = c.fetchall()
		for h in res:
			try:
				iface.AddCacheHeader(h[0])
				loads = loads + 1
			except:
				errors = errors + 1
		sql = "select value from httpcache where type = 1"
		c.execute(sql)
		res = c.fetchall()
		for h in res:
			try:
				iface.AddCacheParameter(h[0])
				loads = loads + 1
			except:
				errors = errors + 1

		c.close()
        	conn.close()
        	print "Loaded %d errrors %d\n" %(loads,errors)


	
class RedisDatabaseModel(DatabaseModel):

	def createDatabaseModel(self):
		pass

	def insertFileOnDatabase(self,filename):
                errors = 0
                inserts = 0
                f = open(filename)
                lines = f.readlines()

		r_server = redis.Redis("localhost")
                for l in lines:
                        if(("Header(" in l)and(")matchs" in l)):
                                i = l.find("Header(")
                                j = l.find(")matchs")
                                value = l[i+7:j]
                                r_server.lpush("headers",value)   
 
                        if(("Parameter(" in l)and(")matchs" in l)):
                                i = l.find("Parameter(")
                                j = l.find(")matchs")
                                value = l[i+10:j]
                                r_server.lpush("parameters",value)   

		print "Total headers %d" % r_server.llen("headers")	
		print "Total parameters %d" % r_server.llen("parameters")	
                f.close()
                print "Total inserts %d errors %d\n" %(inserts,errors)

        def insertPvfeHttpCache(self,iface,update=False):
                total_h = 0
                total_p = 0

		r_server = redis.Redis("localhost")

		if(not update):
			r_server.delete("headers")	 
			r_server.delete("parameters")	 

                cache = iface.GetCacheHeaders()
                if(cache != None):
                        for h in cache:
				total_h = total_h + 1
                         	r_server.lpush("headers",h)
 
                cache = iface.GetCacheParameters()
                if(cache != None):
                        for h in cache:
				total_p = total_p + 1
				r_server.lpush("parameters",h)

		print "Added to database %d" % (total_h + total_p )
		print "Total headers on database %d" % r_server.llen("headers")	
		print "Total parameters on database %d" % r_server.llen("parameters")	

        def insertHttpCachePvfe(self,iface):
                total_h = 0
                total_p = 0

		r_server = redis.Redis("localhost")

		headers = r_server.lrange("headers",0,r_server.llen("headers"))
		for header in headers:
			total_h = total_h + 1
			iface.AddCacheHeader(header)
		parameters = r_server.lrange("parameters",0,r_server.llen("parameters"))
		for param in parameters:
			total_p = total_p + 1
			iface.AddCacheParameter(param)

		print "Added to http cache %d" % (total_h + total_p )


def showPvfeHttpCache(iface):
	
	cache = iface.GetCacheHeaders()
	print "Http cache headers"
	if (cache != None):
		for h in cache:
			print "\tHeader(%s)" % h
	print "Http cache parameters"
	cache = iface.GetCacheParameters()
	if(cache!=None):
		for h in cache:
			print "\tParameter(%s)" % h


def GetDbusInterface():
	bus = dbus.SessionBus()
        try:
        	s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
        except:
                print "No Filter engine available on the bus"
                sys.exit(-1)
        d = dbus.Interface(s,dbus_interface='polyvaccine.filter.http.cache')
	return d

	
if __name__ == '__main__':
	usage = 'httpcache.py [OPTIONS]"'

	parser = optparse.OptionParser(usage=usage)

    	parser.add_option('-f', '--filename', dest='filename',
                      help='Filename with the urls and parameters.')
    	parser.add_option('-m', '--mysql', dest='is_mysql', action='store_true',
                      help='Use Mysql connection to store the data.')
    	parser.add_option('-r', '--redis', dest='is_redis', action='store_true',
                      help='Use Redis connection to store the data.')
    	parser.add_option('-c', '--create', dest='create_database', action='store_true',
                      help='Create a database model.')
    	parser.add_option('-l', '--load', dest='load_database', action='store_true',
                      help='Loads the database model on the pvfe.')
    	parser.add_option('-i', '--insert', dest='insert_database', action='store_true',
                      help='Inserts the pvfe cache on the database model.')
    	parser.add_option('-u', '--update', dest='update_database', action='store_true',
                      help='Updates the pvfe cache on the database model.')

    	options, args = parser.parse_args()

	if(options.is_mysql):
		print "Using Mysql datamodel"
		data = MysqlDatabaseModel()
	elif (options.is_redis):
		print "Using Redis datamodel"
		data = RedisDatabaseModel()
	else:
		print "Use at least one database type."
		sys.exit(-1)

	if(options.filename):
		data.insertFileOnDatabase(options.filename)
		sys.exit(0)

	if(options.create_database):
		data.createDatabaseModel()
	elif(options.insert_database):
		iface = GetDbusInterface()
		data.insertPvfeHttpCache(iface)
	elif(options.update_database):
		iface = GetDbusInterface()
		data.insertPvfeHttpCache(iface,update=True)
	elif(options.load_database):
		iface = GetDbusInterface()
                data.insertHttpCachePvfe(iface)
	else:		
		iface = GetDbusInterface()
		showPvfeHttpCache(iface)

	sys.exit(0)	
