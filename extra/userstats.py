__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2009 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Get the stats of an interface 
#
import getopt
import sys
import numpy
import os

def usage():
        print "Use: python %s [OPTIONS]" %sys.argv[0]
        print "Options"
        print "\t-f <file>                 Users statistics file name(users.info)."
        print "\t-s <statistic>            Statistic Name"
        print "\t-a <value>                Value of the statistic."
	print "\n"
	print "\t-v                        Show verbose messages."
	print "\n"

def parseArguments():
	verbose = 0
	filename = None	
	statistic = None
	stat_value = None

        try:
                opts, args = getopt.getopt(sys.argv[1:], "vf:s:a:")
        except getopt.GetoptError, err:
                print str(err) # will print something like "option -a not recognized"
                usage()
                sys.exit(2)
        for o, a in opts:
                if o in ("-v"):
                        verbose = verbose +1
                elif o in ("-s"):
                     	statistic = a 
                elif o in ("-a"):
                    	stat_value = int(a) 
                elif o in ("-f"):
                	filename = a	
                else:
                        assert False, "unhandled option"

	if(filename == None):
		usage()
		sys.exit(-1)

	return filename,statistic,stat_value,verbose


def loadStatistics(filename):
        
        l_request = list()
        l_duration = list()
        l_requesthits = list()
        l_requestfail = list()
        l_pathhits = list()
        l_pathfails = list()
        l_flows = list()
        
        #ip,request,duration,cost,requesthits,requestfail,pathhits,pathfails,flows,sreach
        
        f = open(filename)
        lines = f.readlines()
        for line in lines: 
                if(line[0] == "#"):
                        continue
                ip,req,dur,cost,reqh,reqf,path,patf,flows,sre = line.split(",")
                l_request.append(int(req))
                l_duration.append(int(dur))
                l_requesthits.append(int(reqh))
                l_requestfail.append(int(reqf))
                l_pathhits.append(int(path))
                l_pathfails.append(int(patf))
                l_flows.append(int(flows))

	f.close()
	return numpy.average(l_request),numpy.std(l_request),numpy.max(l_request),\
	numpy.average(l_duration),numpy.std(l_duration),numpy.max(l_duration),\
	numpy.average(l_requesthits),numpy.std(l_requesthits),numpy.max(l_requesthits),\
	numpy.average(l_requestfail),numpy.std(l_requestfail),numpy.max(l_requestfail),\
	numpy.average(l_pathhits),numpy.std(l_pathhits),numpy.max(l_pathhits),\
	numpy.average(l_pathfails),numpy.std(l_pathfails),numpy.max(l_pathfails),\
	numpy.average(l_flows),numpy.std(l_flows),numpy.max(l_flows)

def checkStatistics(filename,stats):
	items = 0
	filter_items = 0
        f = open(filename)
        lines = f.readlines()
        for line in lines:
                if(line[0] == "#"):
                        continue
		items = items + 1
                ip,request,duration,cost,reqquest_hits,reqquest_fail,path,patf,flows,sre = line.split(",")
		matchs = 0
		for s in stats:
			name = s[0]
			value = s[1]
			if(int(locals()[name]) > value):
			#	filter_items = filter_items + 1
				matchs = matchs + 1
				#print "IP",ip,request,duration,cost,flows	
			else:
				break
		if(matchs == len(stats)):
			filter_items = filter_items + 1
			os.system("whois %s | grep -i netname" % ip)
			print "IP",ip,request,duration,cost,flows	
			
	print "Total",items,"filtered",filter_items
        f.close()
	
	
if __name__ == '__main__':

	filename,statistic,statistic_value,verbose = parseArguments()

	print "yeah"
	avg_request,std_request,max_request,avg_duration,std_duration,max_duration,\
	avg_req_h,std_req_h,max_req_h,avg_req_f,std_req_f,max_req_f,\
	avg_path_h,std_path_h,max_path_h,avg_path_f,std_path_f,max_path_f,\
	avg_flows,std_flows,max_flows = loadStatistics(filename)

	stats = list()
	stats.append(("request",72))
	stats.append(("flows",184))

	checkStatistics(filename,stats)	

	print "Avg request:",avg_request,"Std:",std_request,"Max:",max_request
	print "Avg request hits:",avg_req_h,"Std:",std_req_h,"Max:",max_req_h
	print "Avg request fails:",avg_req_f,"Std:",std_req_f,"Max:",max_req_f
	print "Avg path hits:",avg_path_h,"Std:",std_path_h,"Max:",max_path_h
	print "Avg path fails:",avg_path_f,"Std:",std_path_f,"Max:",max_path_f
	print "Avg duration:",avg_duration,"Std:",std_duration,"Max:",max_duration
	print "Avg flows:",avg_flows,"Std:",std_flows,"Max:",max_flows


	sys.exit(0)	
