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

def debug(c,level = 0):
	pv.GACH_SetStatisticsLevel(c,level)
        pv.GACH_Stats(c)

class Test_01(unittest.TestCase):

    	def setUp(self):
		self.c = pv.GACH_Init()
			
	def tearDown(self):
		pv.GACH_Destroy(self.c)

	def test_01_1(self):
                "Test the graph with the same URI a retransmision "
		uri_1 = "GET index.html HTTP1"
		
		g = pv.GACH_AddBaseLink(self.c,uri_1)
		n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_1,10)
	
		#debug(self.c,3)
		self.assertEqual(self.c.total_links,1)
		self.assertEqual(self.c.total_nodes,1)
		self.assertEqual(self.c.total_fails,0)
		self.assertEqual(self.c.total_hits,0)

		cost = pv.GACH_GetLinkCost(self.c,uri_1,uri_1)
		self.assertEqual(cost , 10)

	def test_01_2(self):
		"Test the graph with two URIs and one link fail"
		uri_1 = "GET index.html HTTP1"
		uri_2 = "GET /imagenes/pepe.png HTTP1"
		#debug(self.c)

		g = pv.GACH_AddBaseLink(self.c,uri_1)
		n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_2,10)

		self.assertEqual(self.c.total_links,1)
		cost = pv.GACH_GetLinkCost(self.c,uri_1,uri_1)
		self.assertEqual(self.c.total_hits,0)
		self.assertEqual(self.c.total_fails,1)
		self.assertEqual(cost,-1)	
		#debug(self.c,3)

	def test_01_3(self):
		"Test 4 consecutive URIs"
		uri_1= "GET index.php HTTP1"
		uri_2= "GET /imagenes/elfary.jpg HTTP1"
		uri_3= "GET /imagenes/torrente.png HTTP1"
		uri_4= "POST form.php HTTP1"
	

                g = pv.GACH_AddBaseLink(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLink(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLink(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_4,100000)

		#debug(self.c,3)	
                self.assertEqual(self.c.total_links,3)
                self.assertEqual(self.c.total_nodes,4)
                self.assertEqual(self.c.total_fails,0)
                self.assertEqual(self.c.total_hits,0)

        def test_01_4(self):
                "Test 4 consecutive URIs and check with an update"
                uri_1= "GET index.php HTTP1"
                uri_2= "GET /imagenes/elfary.jpg HTTP1"
                uri_3= "GET /imagenes/torrente.png HTTP1"
                uri_4= "POST form.php HTTP1"

                g = pv.GACH_AddBaseLink(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLink(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLink(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_4,10000)

	        cost = pv.GACH_GetLinkCost(self.c,uri_3,uri_4)
                self.assertEqual(self.c.total_hits,1)
                self.assertEqual(self.c.total_fails,0)
                self.assertEqual(cost,10000)

		g = pv.GACH_GetBaseLink(self.c,uri_3)
		n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_4,100)

	        cost = pv.GACH_GetLinkCost(self.c,uri_3,uri_4)
                self.assertEqual(self.c.total_hits,2)
                self.assertEqual(self.c.total_fails,0)
                self.assertEqual(cost,100)

	def test_01_5(self):
		"Test 5 consecutive URIs with two different patchs, check grapcache.viz file"
                uri_1= "GET index.php HTTP1"
                uri_2= "GET /imagenes/elfary.jpg HTTP1"
                uri_3= "GET /imagenes/torrente.png HTTP1"
                uri_4= "POST form.php HTTP1"
                uri_5= "GET /somepath/1.php HTTP1"
                uri_6= "GET /somepath/2.php HTTP1"

                g = pv.GACH_AddBaseLink(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLink(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLink(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_4,10000)
                
		g = pv.GACH_AddBaseLink(self.c,uri_4)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_5,100)

		g = pv.GACH_AddBaseLink(self.c,uri_4)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_6,1)

                self.assertEqual(self.c.total_links,5)
                self.assertEqual(self.c.total_nodes,6)
		debug(self.c,3)
	
class Test_02(unittest.TestCase):

        def setUp(self):
                self.c = pv.GACH_Init()
		self.f = pv.FLPO_Init()

        def tearDown(self):
                pv.GACH_Destroy(self.c)
		pv.FLPO_Destroy(self.f)

        def test_02_1(self):
                "Test one flow whit several URIs"
                uri_1= "GET index.php HTTP1"
                uri_2= "GET /imagenes/elfary.jpg HTTP1"
                uri_3= "GET /imagenes/torrente.png HTTP1"
                uri_4= "POST form.php HTTP1"
                uri_5= "GET /somepath/1.php HTTP1"
                uri_6= "GET /somepath/2.php HTTP1"

		flow = pv.FLPO_GetFlow(self.f)

                g = pv.GACH_AddBaseLink(self.c,uri_1)
		flow.lasturi = uri_1
		g = pv.GACH_GetBaseLink(self.c,flow.lasturi)
                n = pv.GACH_AddGraphNodeFromLink(self.c,g,uri_2,10)

		pv.FLPO_AddFlow(self.f,flow)

                self.assertEqual(self.c.total_links,1)
                self.assertEqual(self.c.total_nodes,2)
                #debug(self.c,2)

	def test_02_2(self):
		"Test several URIs on a circle graph"
		uris = list()
              	uris.append("GET index1.php HTTP1")
              	uris.append("GET index2.php HTTP1")
              	uris.append("GET index3.php HTTP1")
              	uris.append("GET index4.php HTTP1")
              	uris.append("GET index5.php HTTP1")
              	uris.append("GET index6.php HTTP1")

		i = 10
		flow = pv.FLPO_GetFlow(self.f)
		self.assertNotEqual(flow,None)
		for idx in xrange(0,len(uris)-1):
			flow.lasturi = uris[idx]
			g = pv.GACH_AddBaseLink(self.c,uris[idx])
                	n = pv.GACH_AddGraphNodeFromLink(self.c,g,uris[idx+1],i)
			i = i * 2

		g = pv.GACH_GetBaseLink(self.c,uris[idx+1])
               	n = pv.GACH_AddGraphNodeFromLink(self.c,g,uris[0],0)
		pv.FLPO_AddFlow(self.f,flow)

                #debug(self.c,3)
                self.assertEqual(self.c.total_links,6)
                self.assertEqual(self.c.total_nodes,6)
                #debug(self.c,3)


	
if __name__ == '__main__':
	print "Testing the graph cache"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
	result=testrunner.BasicTestRunner().run(suite)
	
