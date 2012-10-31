#!/usr/bin/env python
#
# Polyvaccine - PolyFilter engine.
#                                                              
# Copyright (C) 2009  Luis Campo Giralte 
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2009 
#
"""This script manage the main functions of the polyfilter engine"""
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import polyfilter as pf
from optparse import OptionParser
import time

def parseOptions():
        """Parse the user options"""

        usage = "Usage: %prog [options]"

        p = OptionParser(usage)

        p.add_option("-I", "--interface", dest="interface", default=None,
                help="Sets the interface for listen")

        return p


if __name__ == '__main__':

        parser = parseOptions()
        (options, args) = parser.parse_args()
        if(options.interface == None):
                parser.error("Argument is required")
                sys.exit(1)

	pf.POFR_Init();

	pf.POFR_SetSource(options.interface)

	# TODO
	# Use the functions of the polyfilter.h
	# in order to fix with your requirements.
	#

	pf.POFR_EnableAnalyzers("http")
	pf.POFR_SetHTTPSourcePort(80)
	# pf.POFR_AddDetectorNode("polyvaccine.detector","/polyvaccine/detector");

	# For using multicore architecture
	pf.POFR_AddDetectorNode("polyvaccine.detector0","/polyvaccine/detector0");
	pf.POFR_AddDetectorNode("polyvaccine.detector1","/polyvaccine/detector1");
	# pf.POFR_AddDetectorNode("polyvaccine.detector2","/polyvaccine/detector2");
	# pf.POFR_AddDetectorNode("polyvaccine.detector3","/polyvaccine/detector3");

	# General options
	# POFR_SetExitOnPcap - Exists when the pcap file is process
	# POFR_EnableAnalyzers - Enable the analyzer (http,sip or ddos).
	# POFR_Stats - Show the statistics
	# POFR_Start - Starts the engine
	# POFR_Stop - Stops the engine
	# 
	# POFR_SetStatisticsLevel - increases the level of the statistics
	# POFR_SetMode - sets the functional mode(detection,hibrid,update)
	# POFR_SetInitialFlowsOnPool - sets the number of flows on the pools
	# POFR_SetInitialUsersOnPool - sets the number of users on the pools 
	#
	#
	# Functions related to the polymorphic engine
	# POFR_AddToHTTPCache - Add a parameter or uri to the cache
	# POFR_SetHTTPSourcePort
	# POFR_SetForceAnalyzeHTTPPostData 
	# POFR_ShowUnknownHTTP 
	# POFR_SetHTTPStatisticsLevel
	#
	# Functions related to the SIP analyzer

	# main functions
	pf.POFR_Start()
	try:
		pf.POFR_Run()
	except (KeyboardInterrupt, SystemExit):
               	pf.POFR_Stop()

	pf.POFR_Stats()	
	pf.POFR_Destroy()
	
	sys.exit(0)
