__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import random
import ctypes
import sys
sys.path.append("../src/core/")
import polyvaccine as p
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		self.pool = p.FLPO_Init()
		
	def tearDown(self):
		p.FLPO_Destroy(self.pool)

	def test_01_1(self):
		"Test the flowpool "
		value = p.FLPO_GetNumberFlows(self.pool)
		temp = list()
		p.FLPO_DecrementFlowPool(self.pool,1000)
		for i in xrange(0,1000):
			h = p.FLPO_GetFlow(self.pool)
			temp.append(h)

		self.assertEqual(value-2000,p.FLPO_GetNumberFlows(self.pool))
		for h in temp:
			p.FLPO_AddFlow(self.pool,h)

		self.assertEqual(value-1000,p.FLPO_GetNumberFlows(self.pool))

	def test_01_2(self):
		"Test the memorypool "
		m = p.MEPO_Init()
		value = p.MEPO_GetNumberMemorySegments(m)
                temp = list()
                p.MEPO_DecrementMemoryPool(m,1000)
                for i in xrange(0,1000):
                        seg = p.MEPO_GetMemorySegment(m)
                        temp.append(seg)

                self.assertEqual(value-2000,p.MEPO_GetNumberMemorySegments(m))
		
		p.MEPO_Destroy(m)
		del temp		

	def test_01_3(self):
		"Testing memorysegments with small size segments"
		s = p.MESG_InitWithSize(10)
		self.assertEqual(s.real_size ,10)		
		self.assertEqual(s.virtual_size ,0)		
		url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
		p.MESG_AppendPayloadNew(s,url,len(url))
		self.assertEqual(s.virtual_size ,len(url))		
		self.assertEqual(s.real_size ,len(url))		

		# Now add parameters to the segment
		#print s.mem
		param = "Host: 2222222222222333333333333333333333333333333333333333333"
		p.MESG_AppendPayloadNew(s,param,len(param))
		self.assertEqual(s.virtual_size,len(url)+len(param))	
		self.assertEqual(s.real_size,len(url)+len(param))	
		p.MESG_Destroy(s)

	def test_01_4(self):
                "Testing memorysegments with big size segments I"
                s = p.MESG_InitWithSize(500)
                self.assertEqual(s.real_size ,500)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayloadNew(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,500)

                # Now add parameters to the segment
                param = "Host: 2222222222222333333333333333333333333333333333333333333"
                p.MESG_AppendPayloadNew(s,param,len(param))
                self.assertEqual(s.virtual_size,len(url)+len(param))
                self.assertEqual(s.real_size,500)
                p.MESG_Destroy(s)

	def test_01_5(self):
                "Testing memorysegments with big size segments II"
                s = p.MESG_InitWithSize(10)
                self.assertEqual(s.real_size ,10)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayloadNew(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,len(url))

                # Now add parameters to the segment
                param = "Host: 2222222222222333333333333333333333333333333333333333333"
                p.MESG_AppendPayloadNew(s,param,len(param))
                self.assertEqual(s.virtual_size,len(url)+len(param))
                self.assertEqual(s.real_size,len(url)+len(param))
                p.MESG_Destroy(s)

	def test_01_6(self):
                "Testing memorysegments with big size segments III"
                s = p.MESG_InitWithSize(100)
                self.assertEqual(s.real_size ,100)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayloadNew(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,100)
		value = s.virtual_size
		for i in xrange(0,10):
                	# Now add parameters to the segment
                	param = "Host: 2222222222222333333333333333333333333333333333333333333"
			value += len(param)	
                	p.MESG_AppendPayloadNew(s,param,len(param))

                self.assertEqual(s.virtual_size ,value)
                self.assertEqual(s.real_size ,value)

	def test_01_7(self):
		"Testing several resets on the same memory chunk"
		s = p.MESG_InitWithSize(50)
                self.assertEqual(s.real_size ,50)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayloadNew(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,50)
		# Now reusing the memory chunk
		p.MESG_Reset(s)
                self.assertEqual(s.virtual_size ,0)
                self.assertEqual(s.real_size ,50)
		p.MESG_Reset(s)	
                self.assertEqual(s.virtual_size ,0)
                self.assertEqual(s.real_size ,50)
		# Now appending
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n" \
                	"GET /somepath/somewhere/on/some/server HTTP 1.1\n" \
                	"GET /somepath/somewhere/on/some/server HTTP 1.1\n" \
                	"GET /somepath/somewhere/on/some/server HTTP 1.1\n" \
                	"GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayloadNew(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,len(url))
		p.MESG_Reset(s)
		p.MESG_Reset(s)
		p.MESG_Reset(s)


class Test_02(unittest.TestCase):

    	def setUp(self):
		self.fp = p.FLPO_Init()
		self.mp = p.MEPO_Init()

	def tearDown(self):
		p.FLPO_Destroy(self.fp)
		p.MEPO_Destroy(self.mp)

	def test_02_1(self):
		flow = p.FLPO_GetFlow(self.fp)
		memory = p.MESG_InitWithSize(5) 
		#memory = p.MEPO_GetMemorySegment(self.mp)

		p.GEFW_SetMemorySegment(flow,memory);

		buf = "buuuuuuuuuuaaaaaaaaaaaaeeeeeeeeeeeee"
		size = len(buf)
		p.MESG_AppendPayloadNew(flow.memory,buf,size);
		p.MESG_AppendPayloadNew(flow.memory,buf,size);
	
		# Now analyze the segment memory

		# reset the memory
		p.MESG_Reset(flow.memory)
		flow.memory = None
		p.GEFW_Reset(flow)
                self.assertEqual(memory.virtual_size ,0)
                self.assertEqual(memory.real_size ,size * 2)

		# release the memory segment to the memory pool
		p.MEPO_AddMemorySegment(self.mp,memory)
		memory = p.MEPO_GetMemorySegment(self.mp)	
                self.assertEqual(memory.virtual_size ,0)
                self.assertEqual(memory.real_size ,size * 2)
	
	def test_02_2(self):
		l = list()

		for i in xrange(1,40):
			flow = p.FLPO_GetFlow(self.fp)
			mem = p.MEPO_GetMemorySegment(self.mp)	

			p.GEFW_SetMemorySegment(flow,mem)
		
			junk_len = 1024 * i
			junk =  (("%%0%dX" % (junk_len * 2)) % random.getrandbits(junk_len * 8)).decode("hex")	

			p.MESG_AppendPayloadNew(flow.memory,junk,junk_len)

			l.append(flow)

		for i in xrange(1,10):
			flow = l.pop(i)
	                p.MESG_Reset(flow.memory)
			memory = flow.memory
       	         	flow.memory = None
                	p.GEFW_Reset(flow)
			p.MEPO_AddMemorySegment(self.mp,memory)
			p.FLPO_AddFlow(self.fp,flow)	

		l.reverse()
		for flow in l:
			p.MESG_Reset(flow.memory)
			memory = flow.memory
			flow.memory = None
                	p.GEFW_Reset(flow)
			p.MEPO_AddMemorySegment(self.mp,memory)
			p.FLPO_AddFlow(self.fp,flow)	

				
if __name__ == '__main__':
	print "Testing polyvaccine interfaces"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
#	unittest.main()
	result=testrunner.BasicTestRunner().run(suite)
	
