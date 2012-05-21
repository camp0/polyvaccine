__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
""" Unit test for the ddos analyzer and the graph cache """
import dbus
import time
import ctypes
import sys
sys.path.append("../src/core/")
import polyfilter as pv
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		self.c = pv.GACH_Init()
			
	def tearDown(self):
		pv.GACH_Destroy(self.c)

	def test_01_1(self):
                "Test the graph with the same URI "
		uri_1 = "GET index.html HTTP1"

		pv.GACH_AddLink(self.c,uri_1,uri_1,10)
		self.assertEqual(self.c.total_links,1)
		self.assertEqual(self.c.total_fails,0)
		self.assertEqual(self.c.total_hits,0)

		cost = pv.GACH_GetLinkCost(self.c,uri_1,uri_1)
		self.assertEqual(cost , 10)

	def test_01_2(self):
		"Test the graph with two URIs"
		uri_1 = "GET index.html HTTP1"
		uri_2 = "GET /imagenes/pepe.png HTTP1"

		pv.GACH_AddLink(self.c,uri_1,uri_2,10)
		self.assertEqual(self.c.total_links,1)
		cost = pv.GACH_GetLinkCost(self.c,uri_1,uri_1)
		self.assertEqual(self.c.total_hits,0)
		self.assertEqual(self.c.total_fails,1)
		self.assertEqual(cost,-1)	

if __name__ == '__main__':
	print "Testing the graph cache"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
	result=testrunner.BasicTestRunner().run(suite)
	
