__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2011 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import dbus
import time
import ctypes
import sys
sys.path.append("../src/detection/")
sys.path.append("../src/core/")
import polyfilter as pv
import polydetector as d 
import unittest
import testrunner
import subprocess
import platform

class Test_01(unittest.TestCase):

    	def setUp(self):
		pass
		#d.SYSU_Init()	
	def tearDown(self):
		pass
		#d.SYSU_Destroy()	

	def test_01_1(self):
                "Test the pvde by sending 5 exploits "
                pp = subprocess.Popen(["../src/detection/pvde"])

                time.sleep(1)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.detector', '/polyvaccine/detector')
                d = dbus.Interface(s,dbus_interface='polyvaccine.detector')
		time.sleep(1)

		arch = platform.architecture()[0]
		if("32" in arch):
			for i in xrange(0,5):
				subprocess.Popen(["../src/detection/sendexploit","-c","6"],stdout=None)
				time.sleep(0.01)	
		elif("64" in arch):
			for i in xrange(0,5):
				subprocess.Popen(["../src/detection/sendexploit","-c","9"],stdout=None)
				time.sleep(0.09)
		value = d.GetProperty("ShellcodesDetected")
                pp.kill()
                pp.wait()
		self.assertEqual(value,5)

        def test_01_2(self):
                "Test the pvde by sending 1 exploits with incorrect offset"
                pp = subprocess.Popen(["../src/detection/pvde"])

                time.sleep(1)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.detector', '/polyvaccine/detector')
                d = dbus.Interface(s,dbus_interface='polyvaccine.detector')
                time.sleep(1)

                arch = platform.architecture()[0]
                if("64" in arch):
                	subprocess.Popen(["../src/detection/sendexploit","-c","1","-o","8"],stdout=None)
                        time.sleep(0.1)

                value = d.GetProperty("ShellcodesDetected")
                pp.kill()
                pp.wait()
                self.assertEqual(value,0)


        def test_01_3(self):
                "Test the pvde by sending 1 HTTP request."
                pp = subprocess.Popen(["../src/detection/pvde"])

                time.sleep(1)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.detector', '/polyvaccine/detector')
                d = dbus.Interface(s,dbus_interface='polyvaccine.detector')
                time.sleep(1)

                arch = platform.architecture()[0]
                if("64" in arch):
                        subprocess.Popen(["../src/detection/sendexploit","-c","15"],stdout=None)
                        time.sleep(0.1)

                value = d.GetProperty("ShellcodesDetected")
                pp.kill()
                pp.wait()
                self.assertEqual(value,0)

class Test_02(unittest.TestCase):

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_02_1(self):
		"Test the pvde and the pvfe together"
                pvde = subprocess.Popen(["../src/detection/pvde"])
                time.sleep(0.5)
                bus = dbus.SessionBus()
                s = bus.get_object('polyvaccine.detector', '/polyvaccine/detector')
                pvde_d = dbus.Interface(s,dbus_interface='polyvaccine.detector')
		time.sleep(0.5)

                pvfe = subprocess.Popen(["../src/core/pvfe","-i","./pcapfiles/http_slashdot.pcap","-p 80","-e"])
                time.sleep(0.5)
		value1 = pvde_d.ShellcodesDetected()
		value2 = pvde_d.ExecutedSegments()
		time.sleep(1)
		pvde.kill()
		pvde.wait()
		self.assertEqual(value1,0)
		self.assertEqual(value2,1)

if __name__ == '__main__':
	print "Testing the detection engine"
	suite=unittest.TestSuite()
    	#suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_03))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
    	#suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
	result=testrunner.BasicTestRunner().run(suite)
	
