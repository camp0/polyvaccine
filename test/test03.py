__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import ctypes
import sys
sys.path.append("../src/opcodes/")
import counter as c 
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		c.COSU_Init()	
	def tearDown(self):
		c.COSU_Destroy()

	def test_01_1(self):
		uri = "GET /dashboard HTTP/1.1"
		value = c.COSU_CheckSuspiciousOpcodes(uri,len(uri))
		self.assertEqual(value,0)

	def test_01_2(self):
		"Testing exploit axiagen.c with bindshell code on port 4141"
		ex = "FROM:\r\nEHLO:\r\nCNIP:\r\nCNPO:\r\nCNHO: " \
    			"\xb8\x96\x05\x08\xb9\x96\x05\x08\xba\x96\x05\x08\xbb\x96\x05\x08" \
    			"\xbc\x96\x05\x08\xbd\x96\x05\x08\xbe\x96\x05\x08\xbf\x96\x05\x08" \
    			"\xc0\x96\x05\x08" \
    			"\x33\xc9\x83\xe9\xeb\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xdc" \
    			"\xc8\x06\xb7\x83\xeb\xfc\xe2\xf4\xed\x13\x55\xf4\x8f\xa2\x04\xdd" \
    			"\xba\x90\x9f\x3e\x3d\x05\x86\x21\x9f\x9a\x60\xdf\xcc\xe5\x60\xe4" \
    			"\x55\x29\x6c\xd1\x84\x98\x57\xe1\x55\x29\xcb\x37\x6c\xae\xd7\x54" \
    			"\x11\x48\x54\xe5\x8a\x8b\x8f\x56\x6c\xae\xcb\x37\x4f\xa2\x04\xee" \
    			"\x6c\xf7\xcb\x37\x95\xb1\xff\x07\xd7\x9a\x6e\x98\xf3\xbb\x6e\xdf" \
    			"\xf3\xaa\x6f\xd9\x55\x2b\x54\xe4\x55\x29\xcb\x37" \
    			"\r\nPASS:\r\n";
		value = c.COSU_CheckSuspiciousOpcodes(ex,len(ex))
		self.assertEqual(value,1)	

	def test_01_3(self):
		"Testing generic x86 syscall for 32 bits opcodes "
		ex = "\x90\x90\x90\x90\x90\xcd\x80\x90\x90"
		
		value = c.COSU_CheckSuspiciousOpcodes(ex,len(ex))
		self.assertEqual(value,1)	
		ex = "\x90\x90\x90\x90\x90\xcd\x90\x90\x90\x00\x00\x00\x00\xcd\x80"
		value = c.COSU_CheckSuspiciousOpcodes(ex,len(ex))
		self.assertEqual(value,1)	
	
	def test_01_4(self):
		"Testing generic x86 syscall for 64 bits opcodes "
		ex = "\x90\x90\x90\x90\x90\x0f\x55\x90\x90"
		
		value = c.COSU_CheckSuspiciousOpcodes(ex,len(ex))
		self.assertEqual(value,1)	
		ex = "\x90\x90\x90\x90\x90\xcd\x90\x90\x90\x00\x00\x00\xaa\xff\xff\x00\xcd\x81\x0f\x55"
		value = c.COSU_CheckSuspiciousOpcodes(ex,len(ex))
		self.assertEqual(value,1)	
	
	
if __name__ == '__main__':
	print "Testing opcodes"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
	result=testrunner.BasicTestRunner().run(suite)
	
