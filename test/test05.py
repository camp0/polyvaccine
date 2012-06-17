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
		
		g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_1,10)

		self.assertEqual(g.key,n.key)
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

		g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_2,10)

		self.assertEqual(g.key+1,n.key)
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
	

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_4,100000)

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

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_4,10000)

	        cost = pv.GACH_GetLinkCost(self.c,uri_3,uri_4)
                self.assertEqual(self.c.total_hits,1)
                self.assertEqual(self.c.total_fails,0)
                self.assertEqual(cost,10000)

		g = pv.GACH_GetBaseLinkUpdate(self.c,uri_3)
		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_4,100)

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

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_2,10)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_2)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_3,110)

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_3)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_4,10000)
                
		g = pv.GACH_AddBaseLinkUpdate(self.c,uri_4)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_5,100)

		g = pv.GACH_AddBaseLinkUpdate(self.c,uri_4)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_6,1)

                self.assertEqual(self.c.total_links,5)
                self.assertEqual(self.c.total_nodes,6)
		#debug(self.c,3)

	def test_01_6(self):
		"Test retransmisions"
                uri_1= "GET index.php HTTP1"
                uri_2= "GET /imagenes/elfary.jpg HTTP1"
		
		# First request of the flow
		g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
		# Second request of the flow
		l = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
		self.assertEqual(g.key,l.key)
			
		# The flow adds the same uri
		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,l,uri_1,0)
		self.assertEqual(g.key,n.key)

		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,l,uri_1,0)
		self.assertEqual(g.key,n.key)
		
		l = pv.GACH_GetBaseLinkUpdate(self.c,uri_1)
		n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,l,uri_2,0)

		self.assertEqual(self.c.total_nodes,2)
		self.assertEqual(self.c.total_links,2)
		#debug(self.c,3)

	
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

                g = pv.GACH_AddBaseLinkUpdate(self.c,uri_1)
		flow.lasturi = uri_1
		g = pv.GACH_GetBaseLinkUpdate(self.c,flow.lasturi)
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uri_2,10)

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
			g = pv.GACH_AddBaseLinkUpdate(self.c,uris[idx])
                	n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uris[idx+1],i)
			i = i * 2

		g = pv.GACH_GetBaseLinkUpdate(self.c,uris[idx+1])
               	n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,uris[0],0)
		pv.FLPO_AddFlow(self.f,flow)

                #debug(self.c,3)
                self.assertEqual(self.c.total_links,6)
                self.assertEqual(self.c.total_nodes,6)
                #debug(self.c,3)

        def test_02_3(self):
                "Test several URIs on a circle graph with repetitions"
		
                g = pv.GACH_AddBaseLinkUpdate(self.c,"GET index1.php HTTP1")
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,"POST leches HTTP",10)
		id1 = g.key
		id2 = n.key
		self.assertEqual(id1 + 1, id2)
                #debug(self.c,3)
		
                g = pv.GACH_GetBaseLinkUpdate(self.c,"POST leches HTTP")
                n = pv.GACH_AddGraphNodeFromLinkUpdate(self.c,g,"GET index1.php HTTP1",10000)

		self.assertEqual(id2, id1 + 1)
                #debug(self.c,3)
                self.assertEqual(self.c.total_links,2)
                self.assertEqual(self.c.total_nodes,2)
                #debug(self.c,3)



class Test_03(unittest.TestCase):

        def setUp(self):
                self.p = pv.PACH_Init()

        def tearDown(self):
                pv.PACH_Destroy(self.p)

        def test_03_1(self):
                "Test path cache"

		path = pv.PACH_AddPath(self.p,"1 2 3")
		path = pv.PACH_AddPath(self.p,"1 2 ")
		path = pv.PACH_AddPath(self.p,"1 2 3 4 5")
		path = pv.PACH_AddPath(self.p,"1 2 3 4 5")

		self.assertEqual(self.p.total_paths, 3)

        def test_03_2(self):
                "Test path cache II"

                path = pv.PACH_AddPath(self.p,"1 2 3")
                path = pv.PACH_AddPath(self.p,"1 2")
                path = pv.PACH_AddPath(self.p,"1 2 3 4 5")

                self.assertEqual(self.p.total_paths, 3)
		path = pv.PACH_GetPath(self.p,"2 3 4")
		self.assertEqual(path ,None)
		path = pv.PACH_GetPath(self.p,"1 2")
		self.assertNotEqual(path,None)

	def test_03_3(self):
		"Test path cache III" 

		cad = ""
		for i in xrange(0,10):
			cad = "%s %d" %(cad ,i)
                	path = pv.PACH_AddPath(self.p,cad)

		self.assertEqual(self.p.total_paths,10)
		cad = ""
		for i in xrange(0,20):
			cad = "%s %d" %(cad,i)
			path = pv.PACH_GetPath(self.p,cad)

		self.assertEqual(self.p.total_paths, 10)
		self.assertEqual(self.p.total_hits, 10)
		self.assertEqual(self.p.total_fails,10)
	
if __name__ == '__main__':
	print "Testing the graph and paht cache"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_03))
	result=testrunner.BasicTestRunner().run(suite)
	
