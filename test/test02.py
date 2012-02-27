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
		p.POFR_SetExitOnPcap(1)
		p.POFR_Start()
		p.POFR_Run()
		p.POFR_Stop()	
		self.assertEqual(0,p.POFR_GetHTTPHeaderCacheHits())		
		self.assertEqual(1,p.POFR_GetHTTPHeaderCacheFails())

        def test_01_2(self):
                "Test the httpcache hits header"
                p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POFR_AddToHTTPCache(0,"GET /dashboard HTTP/1.1")
		p.POFR_SetExitOnPcap(1)
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
		p.POFR_SetExitOnPcap(1)
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()
                self.assertEqual(1,p.POFR_GetHTTPHeaderCacheHits())
                self.assertEqual(0,p.POFR_GetHTTPHeaderCacheFails())
                self.assertEqual(1,p.POFR_GetHTTPParameterCacheHits())
                self.assertEqual(7,p.POFR_GetHTTPParameterCacheFails())

        def test_01_4(self):
                "Test the httpcache hits header and parameter II"
                p.POFR_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POFR_AddToHTTPCache(0,"GET /dashboard HTTP/1.1")
                p.POFR_AddToHTTPCache(1,"Connection: keep-alive")
                p.POFR_AddToHTTPCache(1,"Accept-Encoding: gzip,deflate,sdch")
		p.POFR_SetExitOnPcap(1)
                p.POFR_Start()
                p.POFR_Run()
                p.POFR_Stop()
                self.assertEqual(1,p.POFR_GetHTTPHeaderCacheHits())
                self.assertEqual(0,p.POFR_GetHTTPHeaderCacheFails())
                self.assertEqual(2,p.POFR_GetHTTPParameterCacheHits())
                self.assertEqual(6,p.POFR_GetHTTPParameterCacheFails())



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
		s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
		d = dbus.Interface(s,dbus_interface='polyvaccine.filter')
		state = d.State()
		pp.kill()	
		self.assertTrue(state == "stop")
		pp.wait()

	def test_02_2(self):
                "Test the pvfe with the dbus service methods"
                pp = subprocess.Popen(["../src/core/pvfe","-i","lo","-p 80"])
		
		time.sleep(1)
		bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
                d = dbus.Interface(s,dbus_interface='polyvaccine.filter.httpcache')

		header = ['GET / HTTP/1.1'] 
		param = ['Host: slashdot.org','Accept-Encoding: gzip, deflate','Connection: keep-alive']
		for h in header:
              		d.AddCacheHeader(h)
		for v in param:
			d.AddCacheParameter(v)
		d.Stop()
		d.SetSource("./pcapfiles/http_slashdot.pcap")
		d.Start()
		time.sleep(0.5)
		a = d.HeaderHits() 
		b = d.ParameterHits()
		#print "Header hits",a
		#print "Parameter hits",b	
		d.Stop()
		pp.kill()
		pp.wait()
		self.assertEqual(a,1)
		self.assertEqual(b,68)
	

	def test_02_3(self):
		"Test the pvfe connection manager, one flow on pool"
                pp = subprocess.Popen(["../src/core/pvfe","-i","lo","-p 80"])
                time.sleep(0.5)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
                d = dbus.Interface(s,dbus_interface='polyvaccine.filter.connection')

		# decrease the flow/memory pool to one.
		value = d.FlowsOnPool() - 1
		r = d.DecreaseFlowPool(value)
		self.assertEqual(r,1)
		r = d.DecreaseMemoryPool(value) 
		self.assertEqual(r,1)

		time.sleep(0.5)
                d.Stop()
                d.SetSource("./pcapfiles/http_slashdot.pcap")
		d.Start()
		time.sleep(0.5)
		fa = d.FlowAcquires()
		fr = d.FlowReleases()
		fp = d.FlowsOnPool()
		fe = d.FlowErrors()
		#print "Flow acquires",fa
		#print "Flow releases",fr
		#print "Flows on pool",fp
		#print "Flow errors",fe
                pp.kill()
                pp.wait()
		self.assertEqual(fa,1)
		self.assertEqual(fr,0)
		self.assertEqual(fp,0)
		self.assertEqual(fe,498)

        def test_02_4(self):
                "Test the pvfe connection manager, five flowis on pool"
                pp = subprocess.Popen(["../src/core/pvfe","-i","lo","-p 80"])
                time.sleep(0.5)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.filter', '/polyvaccine/filter')
                d = dbus.Interface(s,dbus_interface='polyvaccine.filter.connection')

                # decrease the flow/memory pool to one.
                value = d.FlowsOnPool() - 5 
                r = d.DecreaseFlowPool(value)
                self.assertEqual(r,1)
                r = d.DecreaseMemoryPool(value)
                self.assertEqual(r,1)

                time.sleep(0.5)
                d.Stop()
                d.SetSource("./pcapfiles/http_slashdot.pcap")
                d.Start()
                time.sleep(0.5)
                fa = d.FlowAcquires()
                fr = d.FlowReleases()
                fp = d.FlowsOnPool()
                fe = d.FlowErrors()
                #print "Flow acquires",fa
                #print "Flow releases",fr
                #print "Flows on pool",fp
                #print "Flow errors",fe
                pp.kill()
                pp.wait()
                self.assertEqual(fa,5)
                self.assertEqual(fr,0)
                self.assertEqual(fp,0)
                self.assertEqual(fe,318)
	
if __name__ == '__main__':
	print "Testing polyvaccine interfaces"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
#    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
#	unittest.main()
	result=testrunner.BasicTestRunner().run(suite)
	
