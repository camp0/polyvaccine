__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import random
import ctypes
import sys
sys.path.append("../src/core/")
import polyfilter as p
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		self.pool = p.FLPO_Init()
		
	def tearDown(self):
		p.FLPO_Destroy(self.pool)

	def test_01_1(self):
		"Test the flowpool I"
		value = p.FLPO_GetNumberFlows(self.pool)
		temp = list()
		p.FLPO_DecrementFlowPool(self.pool,100)
		for i in xrange(0,100):
			h = p.FLPO_GetFlow(self.pool)
			temp.append(h)

		self.assertEqual(value-200,p.FLPO_GetNumberFlows(self.pool))
		for h in temp:
			p.FLPO_AddFlow(self.pool,h)

		self.assertEqual(value-100,p.FLPO_GetNumberFlows(self.pool))

	def test_01_2(self):
		"Test the memorypool I"
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
		p.MESG_AppendPayload(s,url,len(url))
		self.assertEqual(s.virtual_size ,len(url))		
		self.assertEqual(s.real_size ,len(url))		

		# Now add parameters to the segment
		#print s.mem
		param = "Host: 2222222222222333333333333333333333333333333333333333333"
		p.MESG_AppendPayload(s,param,len(param))
		self.assertEqual(s.virtual_size,len(url)+len(param))	
		self.assertEqual(s.real_size,len(url)+len(param))	
		p.MESG_Destroy(s)

	def test_01_4(self):
                "Testing memorysegments with big size segments I"
                s = p.MESG_InitWithSize(500)
                self.assertEqual(s.real_size ,500)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayload(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,500)

                # Now add parameters to the segment
                param = "Host: 2222222222222333333333333333333333333333333333333333333"
                p.MESG_AppendPayload(s,param,len(param))
                self.assertEqual(s.virtual_size,len(url)+len(param))
                self.assertEqual(s.real_size,500)
                p.MESG_Destroy(s)

	def test_01_5(self):
                "Testing memorysegments with big size segments II"
                s = p.MESG_InitWithSize(10)
                self.assertEqual(s.real_size ,10)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayload(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,len(url))

                # Now add parameters to the segment
                param = "Host: 2222222222222333333333333333333333333333333333333333333"
                p.MESG_AppendPayload(s,param,len(param))
                self.assertEqual(s.virtual_size,len(url)+len(param))
                self.assertEqual(s.real_size,len(url)+len(param))
                p.MESG_Destroy(s)

	def test_01_6(self):
                "Testing memorysegments with big size segments III"
                s = p.MESG_InitWithSize(100)
                self.assertEqual(s.real_size ,100)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayload(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,100)
		value = s.virtual_size
		for i in xrange(0,10):
                	# Now add parameters to the segment
                	param = "Host: 2222222222222333333333333333333333333333333333333333333"
			value += len(param)	
                	p.MESG_AppendPayload(s,param,len(param))

                self.assertEqual(s.virtual_size ,value)
                self.assertEqual(s.real_size ,value)

	def test_01_7(self):
		"Testing several resets on the same memory chunk"
		s = p.MESG_InitWithSize(50)
                self.assertEqual(s.real_size ,50)
                self.assertEqual(s.virtual_size ,0)
                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                p.MESG_AppendPayload(s,url,len(url))
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
                p.MESG_AppendPayload(s,url,len(url))
                self.assertEqual(s.virtual_size ,len(url))
                self.assertEqual(s.real_size ,len(url))
		p.MESG_Reset(s)
		p.MESG_Reset(s)
		p.MESG_Reset(s)

        def test_01_8(self):
                "Test the flowpool II"
                value = p.FLPO_GetNumberFlows(self.pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(self.pool)
                        temp.append(h)

		for i in xrange(0,5):
			h = p.FLPO_GetFlow(self.pool)
			self.assertEqual(None,h)

		self.assertEqual(5,self.pool.pool.total_errors)
                for h in temp:
                        p.FLPO_AddFlow(self.pool,h)

		p.FLPO_AddFlow(self.pool,None)
                self.assertEqual(value,p.FLPO_GetNumberFlows(self.pool))

        def test_01_9(self):
                "Test the flowpool III"
		pool = p.FLPO_Init()
                value = p.FLPO_GetNumberFlows(pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(pool)
                        temp.append(h)

                for i in xrange(0,5):
                        h = p.FLPO_GetFlow(pool)
                        self.assertEqual(None,h)

                self.assertEqual(5,pool.pool.total_errors)
                for h in temp:
                        p.FLPO_AddFlow(pool,h)
		
                p.FLPO_AddFlow(pool,None)
                self.assertEqual(value,p.FLPO_GetNumberFlows(pool))
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                self.assertEqual(value-3,p.FLPO_GetNumberFlows(pool))
		p.FLPO_Destroy(pool)

        def test_01_10(self):
                "Test the flowpool IV"
                pool = p.FLPO_Init()
                value = p.FLPO_GetNumberFlows(pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(pool)
                        temp.append(h)

		dir(pool)
                self.assertEqual(0,pool.pool.total_errors)
                for h in temp:
			p.GEFW_Destroy(h)

                self.assertEqual(0,p.FLPO_GetNumberFlows(pool))
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                self.assertEqual(0,p.FLPO_GetNumberFlows(pool))
                p.FLPO_Destroy(pool)

        def test_01_11(self):
                "Testing several copy of small memory chunks"
                s = p.MESG_InitWithSize(10)
                self.assertEqual(s.real_size ,10)
                self.assertEqual(s.virtual_size ,0)

	        url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
		length = len(url)
                p.MESG_AppendPayload(s,url,length)
                self.assertEqual(s.virtual_size ,length)
                self.assertEqual(s.real_size ,length)
		host = "Host: www.somehost.com\n"
		length = length + len(host)

		p.MESG_AppendPayload(s,host,len(host))	
		self.assertEqual(s.virtual_size ,length)		
		self.assertEqual(s.real_size ,length)		
	
		cookie = "Cookie: blablablalbalbalallalakjdfklajdfi"
		l_cookie = len(cookie)
		length = length + l_cookie

		p.MESG_AppendPayload(s,cookie,l_cookie)
		self.assertEqual(s.virtual_size ,length)		
		self.assertEqual(s.real_size ,length)		

		final = url + host + cookie
#		print "-------------------"
#		print "(%s)" % s.mem
#		print "-------------------"
#		print "(%s)" % final
#		print "-------------------"
#		self.assertEqual(len(s.mem),len(final))
		print s.mem
		print str(s.mem)
		self.assertEqual(s.mem,final)		


        def test_01_12(self):
                "Testing small memory chunks and reuse it"
                s = p.MESG_InitWithSize(10)
                self.assertEqual(s.real_size ,10)
                self.assertEqual(s.virtual_size ,0)

                url = "GET /somepath/somewhere/on/some/server HTTP 1.1\n"
                length = len(url)
                p.MESG_AppendPayload(s,url,length)
                self.assertEqual(s.virtual_size ,length)
                self.assertEqual(s.real_size ,length)

		# The segment is reset but still with the last buffered info.
		p.MESG_Reset(s)
		self.assertEqual(s.virtual_size,0)
		self.assertEqual(s.real_size,length)

        def test_01_13(self):
                "Test the memorypool II"
                m = p.MEPO_Init()
                value = p.MEPO_GetNumberMemorySegments(m)
		seg = p.MEPO_GetMemorySegment(m)
                p.MEPO_DecrementMemoryPool(m,value-1)

		self.assertEqual(0,p.MEPO_GetNumberMemorySegments(m))
		seg1 = p.MEPO_GetMemorySegment(m)
		self.assertEqual(None,seg1)
		self.assertEqual(0,p.MEPO_GetNumberMemorySegments(m))
		p.MEPO_AddMemorySegment(m,seg)
		self.assertEqual(1,p.MEPO_GetNumberMemorySegments(m))

		p.MEPO_AddMemorySegment(m,seg1)
		self.assertEqual(1,p.MEPO_GetNumberMemorySegments(m))

                p.MEPO_Destroy(m)
                del m 

class Test_02(unittest.TestCase):

    	def setUp(self):
		self.fp = p.FLPO_Init()
		self.mp = p.MEPO_Init()

	def tearDown(self):
		p.FLPO_Destroy(self.fp)
		p.MEPO_Destroy(self.mp)

	def test_02_1(self):
		"Testing flow and memory segments I"
		flow = p.FLPO_GetFlow(self.fp)
		memory = p.MESG_InitWithSize(5) 
		#memory = p.MEPO_GetMemorySegment(self.mp)

		p.GEFW_SetMemorySegment(flow,memory);

		buf = "buuuuuuuuuuaaaaaaaaaaaaeeeeeeeeeeeee"
		size = len(buf)
		p.MESG_AppendPayload(flow.memory,buf,size);
		p.MESG_AppendPayload(flow.memory,buf,size);
	
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
		"Testing flow and memory segments II"
		l = list()

		for i in xrange(1,40):
			flow = p.FLPO_GetFlow(self.fp)
			mem = p.MEPO_GetMemorySegment(self.mp)	

			p.GEFW_SetMemorySegment(flow,mem)
		
			junk_len = 1024 * i
			junk =  (("%%0%dX" % (junk_len * 2)) % random.getrandbits(junk_len * 8)).decode("hex")	

			p.MESG_AppendPayload(flow.memory,junk,junk_len)

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

class Test_03(unittest.TestCase):

        def setUp(self):
                self.u = p.USPO_Init()

        def tearDown(self):
                p.USPO_Destroy(self.u)

        def test_03_1(self):
                "Testing remove 1000 users from pool"
		l = list()

		value = p.USPO_GetNumberUsers(self.u)
		for i in xrange(0,1000):
               		l.append(p.USPO_GetUser(self.u))

		self.assertEqual(p.USPO_GetNumberUsers(self.u),value-1000)

		for i in xrange(0,1000):
			u = l.pop(0)
			p.USER_Destroy(u)

		self.assertEqual(len(l),0)
	
	def test_03_2(self):
                "Testing remove all users from pool"
		u = p.USPO_Init()

		value = p.USPO_GetNumberUsers(u)
		p.USPO_DecrementUserPool(u,value+100)

		self.assertEqual(0, p.USPO_GetNumberUsers(u))
		user = p.USPO_GetUser(u)
		self.assertEqual(user,None)

		p.USPO_Destroy(u)	
			
        def test_03_3(self):
                "Testing remove all users from pool and add some users"
                u = p.USPO_Init()

                value = p.USPO_GetNumberUsers(u)
                p.USPO_DecrementUserPool(u,value+100)

                self.assertEqual(0, p.USPO_GetNumberUsers(u))
                user = p.USPO_GetUser(u)
                self.assertEqual(user,None)

		for i in xrange(0,100):
			user = p.USER_Init()
			p.USPO_AddUser(u,user)

                self.assertEqual(100, p.USPO_GetNumberUsers(u))

		for i in xrange(0,10):
			user = p.USPO_GetUser(u)
			p.USER_Destroy(user)

		self.assertEqual(90,p.USPO_GetNumberUsers(u))

                p.USPO_Destroy(u)

        def test_03_4(self):
                "Testing remove all users from pool and add 200.000 users" 
		limit = 20
                u = p.USPO_Init()

                value = p.USPO_GetNumberUsers(u)
                p.USPO_DecrementUserPool(u,value+100)

                self.assertEqual(0, p.USPO_GetNumberUsers(u))
                user = p.USPO_GetUser(u)
                self.assertEqual(user,None)

                for i in xrange(0,limit):
                        user = p.USER_Init()
			user.acumulated_cost = i
                        p.USPO_AddUser(u,user)

                self.assertEqual(limit, p.USPO_GetNumberUsers(u))
		l = list()
		for i in xrange(0,p.USPO_GetNumberUsers(u)):
			user = p.USPO_GetUser(u)
			self.assertEqual(user.acumulated_cost, 0)
			l.append(user)

                self.assertEqual(0,p.USPO_GetNumberUsers(u))

		p.USPO_DecrementUserPool(u,limit)
                self.assertEqual(0,p.USPO_GetNumberUsers(u))

                p.USPO_Destroy(u)

        def test_03_4(self):
                "Testing remove users from pool and add to the usertable"
                u = p.USPO_Init()
		t = p.USTA_Init()

		p.USTA_SetUserPool(t,u)
		value1 = p.USPO_GetNumberUsers(u)
		for i in xrange(0,250):
			user = p.USPO_GetUser(u)
			user.ip = i
			#user.ip = ctypes.u_int32_t(i)
			p.USTA_InsertUser(t,user)

		self.assertEqual(t.current_users,250)

		p.USTA_ReleaseUsers(t)
		value2 = p.USPO_GetNumberUsers(u)
		self.assertEqual(t.current_users,0)
		self.assertEqual(value1,value2)	
		p.USTA_Destroy(t)
                p.USPO_Destroy(u)

        def test_03_4(self):
                "Testing move users on one usertable and two userpools"
                u1 = p.USPO_Init()
                u2 = p.USPO_Init()
                t = p.USTA_Init()

                value = p.USPO_GetNumberUsers(u2)
		p.USPO_DecrementUserPool(u2,value)

		self.assertEqual(p.USPO_GetNumberUsers(u2),0)

                value = p.USPO_GetNumberUsers(u1)
                for i in xrange(0,value):
                        user = p.USPO_GetUser(u1)
                        user.ip = i
                        p.USTA_InsertUser(t,user)

		self.assertEqual(p.USPO_GetNumberUsers(u1),0)
		self.assertEqual(p.USPO_GetNumberUsers(u2),0)

                p.USTA_SetUserPool(t,u2)
                self.assertEqual(t.current_users,value)

                p.USTA_ReleaseUsers(t)

		self.assertEqual(0,p.USPO_GetNumberUsers(u1))
		self.assertEqual(value,p.USPO_GetNumberUsers(u2))

                self.assertEqual(t.current_users,0)
                
                p.USTA_Destroy(t)
                p.USPO_Destroy(u1)
                p.USPO_Destroy(u2)


	
if __name__ == '__main__':
	print "Testing polyfilter flowpools and memorypools"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_03))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
#	unittest.main()
	result=testrunner.BasicTestRunner().run(suite)
	
