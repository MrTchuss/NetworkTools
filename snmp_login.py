#!/usr/bin/env python
##############################################################################
# snmp_login.py - scapy script to discover SNMP communities                  #
# 20 May 2012 - Nicolas Biscos (buffer at 0x90 period fr )                   #
#                                                                            #
# Perform a dictionary-based SNMP community brute-force. This can be use as  #
# a lib for get/set SNMP values                                              #
#                                                                            #
# This program is free software: you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation, either version 3 of the License, or          #
# (at your option) any later version.                                        #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the               #
# GNU General Public License for more details.                               #
#                                                                            #
# This should have received a copy of the GNU General Public License         #
# along with this program. If not, see <http://www.gnu.org/licenses/>.       #
##############################################################################

"""
TODO List:
   * Implement output file
   * Implement get-next support for v2c
"""

# Suppress scapy complaints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import string, random, sys, os
from getopt import getopt
from getopt import GetoptError
from threading import Thread
from threading import Lock
from Queue import Queue

versionOid = '.1.3.6.1.2.1.1.1.0'
nameOid = '.1.3.6.1.2.1.1.5.0'

"""
Class to handle SNMP Get/Set request
"""
class Snmp:
   version = 0
   dport = 161
   timeout = 0.5
   dst = '127.0.0.1'
   __error = 0
   __response = ''
   def __init__(self, dst=None, community=None, version=None, dport=None, sport=None, timeout=None):
      if( None != dst ):
         self.dst = dst
      if( None != community ):
         self.community = community
      else:
         self.randomCommunity()
      if( None != version ):
         self.version = version;
      if( None != dport ):
         self.dport = dport;
      if( None != sport ):
         self.sport = sport;
      else:
         self.randomSport();
      if( None != timeout ):
         self.timeout = timeout;

   """
   Generates a randome community name
   @return a random 8-bytes string
   """
   def randomCommunity(self):
         self.community = ''.join([random.choice(string.ascii_uppercase) for x in range(8)])

   """
   Generates a random non-privileged port number
   @return a non privileged port number
   """
   def randomSport(self):
      self.sport = RandInt()
      self.sport.max = 65535
      self.sport.min = 1024
   
   """
   Returns error count
   @return error count
   """
   def error(self):
      return self.__error;

   """
   Returns response string
   @return response string 
   """
   def response(self):
      return self.__response;

   """
   Perform a get/set request. The get/set trigger is the pdu format
   @param pdu SNMP pdu. Do a key/value to trig a set condition
   @return False if no answer received, else True
   """
   def __getset(self, pdu):
      if( None == self.sport ):
         self.randomSport();
      if( None == self.community ):
         self.randomCommunity()
      packet  = IP(dst=self.dst)
      packet /= UDP(sport=self.sport, dport=self.dport)
      packet /= SNMP(version=self.version, community=self.community)
      packet[SNMP].PDU = pdu
      verb = conf.verb;
      conf.verb = 0
      ans = sr1(packet, timeout=self.timeout)
      conf.verb = verb
      if( None == ans ):
         self.__error = 1;
         self.__response = "";
         return False
      elif( ans.haslayer(SNMP) and ans.haslayer(SNMPresponse) ):
         self.__error = ans[SNMP][SNMPresponse].error.val;
         if( 0 != self.__error ):
            self.__response = ""
         elif(ans.haslayer(SNMPvarbind)):
            self.__response = ans[SNMP][SNMPresponse][SNMPvarbind].value.val
         else:
            self.__response = "";
         return True;
      return False;
 
   """
   Send/receive a SNMP Get
   @param oid OID to use
   @return False if no answer received, else True
   """
   def get(self, oid):
      pdu = SNMPget(varbindlist=SNMPvarbind(oid=oid));
      return self.__getset(pdu)
      
   """
   Send/receive a SNMP Set
   @param oid OID to use
   @param value value to set
   @return False if no answer received, else True
   """
   def set(self, oid, value):
      pdu = SNMPset(varbindlist=SNMPvarbind(oid=oid, value=value))
      return self.__getset(pdu)

"""
This Worker class is an independant Thread that picks up in
a synchronized queue the SNMP packet to proceed.
It can be proceed by two different functions (checkCommunityString
and checkCommunityType, that respectiveley check whether the community
name exists, and checks if the community name is RO or RW
"""
class Worker(Thread):
   def __init__(self, queue):
      Thread.__init__(self);
      self.__queue = queue;
      self.daemon = True;
      self.__doStop = False;

   """
   Select the SNMP function processing
   @param function One of checkCommunityString or checkCommunityType
   """
   def setFunction(self, function):
      if( 'checkCommunityString' == function ):
         self.__function = self.checkCommunityString;
      elif( 'checkCommunityType' == function ):
         self.__function = self.checkCommunityType;

   """
   Set the shared thread lock
   @param lock lock object
   """
   def setLock(self, lock):
      self.__lock = lock;

   """
   Set the shared SNMPResults object
   @param results the SNMPResults object
   """
   def setResults(self, results):
      self.__results = results;

   """
   Check if the SNMP server responds to the SNMP object 
   @param snmp a prepared snmp packet
   """
   def checkCommunityString(self, snmp):
      if( snmp.get(versionOid) and 0 == snmp.error() ):
         version = '1'
         if snmp.version == 1:
            version = '2c'
         print '[+] Community %s, version %s, for %s: "%s"' % (snmp.community, version, snmp.dst, snmp.response());
         self.__lock.acquire()
         self.__results.add(snmp.dst, snmp.version, snmp.community);
         self.__lock.release()

   """
   Check if the SNMP server responds to the SNMP object in RW or RO mode
   @param snmp a prepared snmp packet
   """
   def checkCommunityType(self, snmp):
      if( snmp.get(nameOid) and not snmp.error() ):
         name = snmp.response();
         if( snmp.set(nameOid, name) ):
            version = '1'
            if snmp.version == 1:
               version = '2c'
            if( not snmp.error() ):
               access = 'RW';
            else:
               access = 'RO';
            print '[+] Community %s, version %s, for %s is %s' % (community, version, dst, access);
         else:
            print '[!] Something went wrong...'

   """
   Thread main worker method. Pick up an snmp prepared packed in the Queue and process it
   """
   def run(self):
      self.__doStop = False;
      while not self.__doStop:
         snmp = self.__queue.get()
         self.__function(snmp)
         self.__queue.task_done()

   """
   Stop the main worker method. Not sure if it is usefull here...
   """
   def stop(self):
      self.__doStop = True;

"""
Simple container for SNMP check results
"""
class SnmpResult:
   def __init__(self, dst, snmpVersion, communityName):
      self.dst = dst;
      self.communityName = communityName;
      self.snmpVersion = snmpVersion;
   def get(self):
      return self.dst, self.communityName, self.snmpVersion;

"""
Container for multiple SNMP Results. Can be iterated
"""
class SnmpResults:
   def __init__(self):
      self.__rslt = [];

   def add(self, dst, snmpVersion, communityName):
      snmpResult = SnmpResult(dst, snmpVersion, communityName);
      self.__rslt.append(snmpResult);

   def __iter__(self):
      self.__iter = self.__rslt.__iter__();
      return self;

   def next(self):
      snmpResult = self.__iter.next();
      return snmpResult.get();

def doHelp():
   # To add when file support will be implemented
   #Syntax: snmp_login.py [-C communityFileName] [-c communityName] [-d dport] [-s sport] [-o outputFile] [-v snmpVersion] [-w workers] [-t timeout] [-h] target1 [target2 [...]]
   #   -o outputFileName
   #   --output             write results in outputFileName

   print """
Scapy Script to brute force SNMP community names.
The principle is taken from snmp_login Metasploit module. First, a set of SNMP GET request using versionOID is performed to capture the community names.
Then, based on the results, these community names are used to read, then write back the nameOID. Based on the response status, the community is marked as RW or RO.

Syntax: snmp_login.py [-C communityFileName] [-c communityName] [-d dport] [-s sport] [-v snmpVersion] [-w workers] [-t timeout] [-h] target1 [target2 [...]]

Common options:
---------------
   -C communityFileName
   --communityFile=     file containing a list of community to test (tip: use fuzzdb one)

   -c communityName
   --community=         a comma-separated community name list to test (ex: -c private,public,ilmi)

   -d dport
   --dport              UDP destination port if different from 161

   -v version
   --version            a comma-separated version list of snmp protocol to test (ex: -v 1,2c)

   -h
   --help               Display this message and exits

   target               ip to test

Advanced options:
-----------------
   --sport=
   -s sport             UDP source port 
   -t timeout           timeout (no SNMP response back) USE WITH CAUTION !
   -w workersCount      number of thread to use

"""

"""
"""
def parseArgs():
   communityList = ['public', 'private']
   output        = sys.stdout;
   stopOnFirst   = False
   versionList   = [0, 1]
   dport = 161
   sport = None
   workersCount=30
   timeout = 0.5;
   if( 'posix' != os.name ):
      print '[!] Only on linux or unix system'
      sys.exit(-1)
   if( 0 != os.geteuid() ):
      print '[!] Must be root'
      sys.exit(-1);
   try:
      #opts, targetList = getopt(sys.argv[1:], 'c:C:d:s:o:v:w:h', ['community=', 'communityFile=', 'dport=', 'sport=', 'output=', 'help', 'version=']);
      opts, targetList = getopt(sys.argv[1:], 'c:C:d:s:v:t:w:h', ['community=', 'communityFile=', 'dport=', 'sport=', 'help', 'version=']);
   except GetoptError, e:
      print '[!] %s' % str(e);
      sys.exit(-1);
  
   for k, v in opts:
      if( '-c' == k or '--community' == k ):
         communityList = v.split(',');
      elif( '-C' == k or '--communityFile' == k ):
         if( not os.path.exists(v) ):
            print '%s: no such file or directory' % (v)
            sys.exit(-1)
         communityList = open(v, 'r').read(-1).split('\n');
      elif( '-d' == k or '--dport' == k ):
         dport = int(v);
      elif( '-s' == k or '--sport' == k ):
         sport = int(v)
      #elif( '-o' == k or '--output' == k ):
      #   if( os.path.exists(v) ):
      #      print '%s: file exists. Please use a different file name.' % (v)
      #      sys.exit(-1);
      #   output = open(v, 'w');
      elif( '-v' == k or '--version' == k ):
         for version in v.split(','):
            if '1' == version:
               versionList.append(0);
            elif '2c' == version or '2C' == version:
               versionList.append(1);
            else:
               print '[!] Unknown version %s' % (version)
               sys.exit(-1);
      elif( '-t' == k ):
         timeout = float(v);
      elif( '-w' == k ):
         workersCount = int(v);
      elif( '-h' == k or '--help' == k ):
         doHelp();
         sys.exit(0)

   if( 0 == len(targetList) ):
      print '[!] Must define at least one target'
      sys.exit(-1);
   
   return targetList, communityList, output, stopOnFirst, dport, sport, versionList, workersCount, timeout;

if( "__main__" == __name__ ):
   # Retrieve arguments from command line
   targetList, communityList, output, stopOnFirst, dport, sport, versionList, workersCount, timeout =  parseArgs()

   # Creates the sync Queues
   q = Queue()

   # Creates a list of workerss
   workerList = []
   lock = Lock();
   results = SnmpResults()
   for worker in range(workersCount):
      worker = Worker(q);
      worker.setFunction("checkCommunityString")
      worker.setResults(results);
      worker.setLock(lock);
      workerList.append(worker);
      worker.start();

   # Fills the synchronized queue with SNMP prepared packets
   for community in communityList:
      for dst in targetList:
         for version in versionList:
            snmp = Snmp()
            snmp.dport = dport;
            snmp.sport = sport;
            snmp.timeout=timeout
            snmp.dst = dst;
            snmp.version = version;
            snmp.community = community;
            q.put(snmp);
   # Wait for workers to end
   q.join();
   
   # Not sure if it is useful, but stops the workers
   for worker in workerList:
      worker.stop();

   # Initialize new workers for more community type-check work
   print ''
   q = Queue()
   workerList = []
   for worker in range(workersCount):
      worker = Worker(q);
      worker.setFunction("checkCommunityType")
      worker.setResults(None);
      worker.setLock(None);
      workerList.append(worker);
      worker.start();
 
   # Retrieve previously discovered snmp communities and check their types
   for dst, community, version in results:
      snmp = Snmp()
      snmp.dport = dport;
      snmp.sport = sport;
      snmp.timeout=timeout
      snmp.dst = dst;
      snmp.version = version;
      snmp.community = community;
      q.put(snmp);
   # Wait for workers to end
   q.join();

   # Not sure if it is useful, but stops the workers
   for worker in workerList:
      worker.stop();


