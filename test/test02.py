__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import ctypes
import sys
sys.path.append("../src/core/")
import polyvaccine as p
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		p.POEG_Init()
		
	def tearDown(self):
		p.POEG_Destroy()

	def test_01_1(self):
		"Test the httpcache fails header"
		p.POEG_SetSource("./pcapfiles/http_one_get_and_response.pcap")
		p.POEG_Start()
		p.POEG_Run()
		p.POEG_Stop()	
		self.assertEqual(0,p.POEG_GetHttpHeaderCacheHits())		
		self.assertEqual(1,p.POEG_GetHttpHeaderCacheFails())

	def test_01_2(self):
		"Test the httpcache hits header"
		p.POEG_SetSource("./pcapfiles/http_one_get_and_response.pcap")
		p.POEG_AddToHttpCache(0,"GET /dashboard HTTP/1.1")
                p.POEG_Start()
                p.POEG_Run()
                p.POEG_Stop()
                self.assertEqual(1,p.POEG_GetHttpHeaderCacheHits())
                self.assertEqual(0,p.POEG_GetHttpHeaderCacheFails())
		
        def test_01_3(self):
                "Test the httpcache hits header and parameter I"
                p.POEG_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POEG_AddToHttpCache(0,"GET /dashboard HTTP/1.1")
                p.POEG_AddToHttpCache(1,"Connection: keep-alive")
                p.POEG_Start()
                p.POEG_Run()
                p.POEG_Stop()
                self.assertEqual(1,p.POEG_GetHttpHeaderCacheHits())
                self.assertEqual(0,p.POEG_GetHttpHeaderCacheFails())
                self.assertEqual(1,p.POEG_GetHttpParameterCacheHits())
                self.assertEqual(2,p.POEG_GetHttpParameterCacheFails())

        def test_01_4(self):
                "Test the httpcache hits header and parameter II"
                p.POEG_SetSource("./pcapfiles/http_one_get_and_response.pcap")
                p.POEG_AddToHttpCache(0,"GET /dashboard HTTP/1.1")
                p.POEG_AddToHttpCache(1,"Connection: keep-alive")
                p.POEG_AddToHttpCache(1,"Accept-Encoding: gzip,deflate,sdch")
                p.POEG_Start()
                p.POEG_Run()
                p.POEG_Stop()
                self.assertEqual(1,p.POEG_GetHttpHeaderCacheHits())
                self.assertEqual(0,p.POEG_GetHttpHeaderCacheFails())
                self.assertEqual(1,p.POEG_GetHttpParameterCacheHits())
                self.assertEqual(2,p.POEG_GetHttpParameterCacheFails())

	def test_01_5(self):
		"Test ba"			
	
if __name__ == '__main__':
	print "Testing polyvaccine interfaces"
	suite=unittest.TestSuite()
#    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
#	unittest.main()
	result=testrunner.BasicTestRunner().run(suite)
	
