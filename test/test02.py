__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import ctypes,os,signal
import sys
sys.path.append("../src/core/")
import polyvaccine as p
import unittest
import testrunner
import dbus
import subprocess
import time

class Test_01(unittest.TestCase):

    	def setUp(self):
		p.POFR_Init()
	
	def tearDown(self):
		p.POFR_Destroy()

	def test_01_1(self):
		"Test the httpcache fails header"
		p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
		p.POFR_Start()
		p.POFR_Run()
		p.POFR_Stop()	
		self.assertEqual(0,p.POFR_GetHTTPHeaderCacheHits())		
		self.assertEqual(1,p.POFR_GetHTTPHeaderCacheFails())

	def test_01_2(self):
		"Test the httpcache hits header"
		p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
		p.POFR_AddToHTTPCache(0,"GET /dashboard HTTP/1.1")
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()
                self.assertEqual(1,p.POFR_GetHTTPHeaderCacheHits())
                self.assertEqual(0,p.POFR_GetHTTPHeaderCacheFails())
		
        def test_01_3(self):
                "Test the httpcache hits header and parameter I"
                p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POFR_AddToHTTPCache(0,"GET /dashboard HTTP/1.1")
                p.POFR_AddToHTTPCache(1,"Connection: keep-alive")
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()
                self.assertEqual(1,p.POFR_GetHTTPHeaderCacheHits())
                self.assertEqual(0,p.POFR_GetHTTPHeaderCacheFails())
                self.assertEqual(1,p.POFR_GetHTTPParameterCacheHits())
                self.assertEqual(2,p.POFR_GetHTTPParameterCacheFails())

        def test_01_4(self):
                "Test the httpcache hits header and parameter II"
                p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POFR_AddToHTTPCache(0,"GET /dashboard HTTP/1.1")
                p.POFR_AddToHTTPCache(1,"Connection: keep-alive")
                p.POFR_AddToHTTPCache(1,"Accept-Encoding: gzip,deflate,sdch")
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()
                self.assertEqual(1,p.POFR_GetHTTPHeaderCacheHits())
                self.assertEqual(0,p.POFR_GetHTTPHeaderCacheFails())
                self.assertEqual(1,p.POFR_GetHTTPParameterCacheHits())
                self.assertEqual(2,p.POFR_GetHTTPParameterCacheFails())

	def test_01_5(self):
                "Test the httpcache and generates a signaling on the d-bus"
                p.POFR_SetSource("./pcapfiles/http_one_get_slashdot.pcap")
                p.POFR_AddToHTTPCache(0,"GET / HTTP/1.1")
                p.POFR_AddToHTTPCache(1,"Host: slashdot.org")
                p.POFR_AddToHTTPCache(1,"User-Agent: Mozilla/5.0 (Ubuntu; X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0")
                p.POFR_AddToHTTPCache(1,"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                p.POFR_AddToHTTPCache(1,"Accept-Language: es-es,es;q=0.8,en-us;q=0.5,en;q=0.3")
                p.POFR_AddToHTTPCache(1,"Accept-Encoding: gzip, deflate")
                p.POFR_AddToHTTPCache(1,"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7")
                p.POFR_AddToHTTPCache(1,"Referer: http://www.google.com/search?client=ubuntu&channel=fs&q=google.es&ie=utf-8&oe=utf-8")
		p.POFR_AddToHTTPCache(1,"DNT: 1")
		p.POFR_AddToHTTPCache(1,"Connection: keep-alive")
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()

class Test_02(unittest.TestCase):

        def setUp(self):
		pass

        def tearDown(self):
		pass

        def test_02_1(self):
		"Test the pvfe with the dbus service State property"
                pp = subprocess.Popen(["../src/core/pvfe","-i","lo","-p 80"])
		time.sleep(1)
		bus = dbus.SessionBus()
		s = bus.get_object('polyvaccine.engine', '/polyvaccine/engine')
		d = dbus.Interface(s,dbus_interface='polyvaccine.engine')
		state = d.State()
		pp.kill()	
		self.assertTrue(state == "stop")
		pp.wait()

	def test_02_2(self):
                "Test the pvfe with the dbus service methods"
                pp = subprocess.Popen(["../src/core/pvfe","-i","lo","-p 80"])
		
		time.sleep(1)
		bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.engine', '/polyvaccine/engine')
                d = dbus.Interface(s,dbus_interface='polyvaccine.engine.httpcache')

		header = ['GET / HTTP/1.1'] 
		param = ['Host: slashdot.org','Accept-Encoding: gzip, deflate','Connection: keep-alive']
		for h in header:
              		d.AddCacheHeader(h)
		for v in param:
			d.AddCacheParameter(v)
		d.Stop()
		d.SetSource("./pcapfiles/http_slashdot.pcap")
		d.Start()
		a = d.HeaderHits() 
		b = d.ParameterHits()	
		d.Stop()
		pp.kill()
		pp.wait()
		self.assertEqual(a,1)
		self.assertEqual(b,6)
		
if __name__ == '__main__':
	print "Testing polyvaccine interfaces"
	suite=unittest.TestSuite()
#    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
#	unittest.main()
	result=testrunner.BasicTestRunner().run(suite)
	
