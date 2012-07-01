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
   Generates a random community name
   @return a random 8-bytes string
   """
   def randomCommunity(self):
         self.community = ''.join([random.choice(string.ascii_uppercase) for x in xrange(8)])

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
class AbstractWorker(Thread):
   def __init__(self, queue):
      Thread.__init__(self);
      self.__queue = queue;
      self.daemon = True;
      self.__doStop = False;

   """
   To be extended in subclasses
   """
   def _compute(self, snmp):
      pass

   """
   Thread main worker method. Pick up an snmp prepared packed in the Queue and process it
   """
   def run(self):
      self.__doStop = False;
      while not self.__doStop:
         snmp = self.__queue.get()
         self._compute(snmp)
         self.__queue.task_done()

   """
   Stop the main worker method. Not sure if it is usefull here...
   """
   def stop(self):
      self.__doStop = True;

class CheckCommunityStringWorker(AbstractWorker):
   def __init__(self, queue):
      AbstractWorker.__init__(self, queue);

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
   def _compute(self, snmp):
      if( snmp.get(versionOid) and 0 == snmp.error() ):
         version = '1'
         if snmp.version == 1:
            version = '2c'
         print '[+] Community %s, version %s, for %s: "%s"' % (snmp.community, version, snmp.dst, snmp.response());
         self.__results.add(snmp.dst, snmp.version, snmp.community);

class CheckCommunityTypeWorker(AbstractWorker):
   def __init__(self, queue):
      AbstractWorker.__init__(self, queue);

   """
   Check if the SNMP server responds to the SNMP object in RW or RO mode
   @param snmp a prepared snmp packet
   """
   def _compute(self, snmp):
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
            community = snmp.community
            dst = snmp.dst
            print '[+] Community %s, version %s, for %s is %s' % (community, version, dst, access);
         else:
            print '[!] Something went wrong...'

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
   def __init__(self, lock):
      self.__rslt = [];
      self.__lock = lock;

   def add(self, dst, snmpVersion, communityName):
      snmpResult = SnmpResult(dst, snmpVersion, communityName);
      self.__lock.acquire();
      self.__rslt.append(snmpResult);
      self.__lock.release();

   def __iter__(self):
      self.__iter = self.__rslt.__iter__();
      return self;

   def next(self):
      snmpResult = self.__iter.next();
      return snmpResult.get();

class Main():
   def __init__(self):
      pass

   def doHelp(self):
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
   def parseArgs(self):
      self.communityList = ['public', 'private']
      self.output        = sys.stdout;
      self.stopOnFirst   = False
      self.versionList   = [0, 1]
      self.dport = 161
      self.sport = None
      self.workersCount=30
      self.timeout = 0.5;
      if( 'posix' != os.name ):
         print '[!] Only on linux or unix system'
         sys.exit(-1)
      if( 0 != os.geteuid() ):
         print '[!] Must be root'
         sys.exit(-1);
      try:
         #opts, self.targetList = getopt(sys.argv[1:], 'c:C:d:s:o:v:w:h', ['community=', 'communityFile=', 'dport=', 'sport=', 'output=', 'help', 'version=']);
         opts, self.targetList = getopt(sys.argv[1:], 'c:C:d:s:v:t:w:h', ['community=', 'communityFile=', 'dport=', 'sport=', 'help', 'version=']);
      except GetoptError, e:
         print '[!] %s' % str(e);
         sys.exit(-1);
     
      for k, v in opts:
         if( '-c' == k or '--community' == k ):
            self.communityList = v.split(',');
         elif( '-C' == k or '--communityFile' == k ):
            if( not os.path.exists(v) ):
               print '%s: no such file or directory' % (v)
               sys.exit(-1)
            self.communityList = open(v, 'r').read(-1).split('\n');
         elif( '-d' == k or '--dport' == k ):
            self.dport = int(v);
         elif( '-s' == k or '--sport' == k ):
            self.sport = int(v)
         #elif( '-o' == k or '--output' == k ):
         #   if( os.path.exists(v) ):
         #      print '%s: file exists. Please use a different file name.' % (v)
         #      sys.exit(-1);
         #   self.output = open(v, 'w');
         elif( '-v' == k or '--version' == k ):
            for version in v.split(','):
               if '1' == version:
                  self.versionList.append(0);
               elif '2c' == version or '2C' == version:
                  self.versionList.append(1);
               else:
                  print '[!] Unknown version %s' % (version)
                  sys.exit(-1);
         elif( '-t' == k ):
            self.timeout = float(v);
         elif( '-w' == k ):
            self.workersCount = int(v);
         elif( '-h' == k or '--help' == k ):
            self.doHelp();
            sys.exit(0)
   
      if( 0 == len(self.targetList) ):
         print '[!] Must define at least one target'
         sys.exit(-1);
   
   """
   Creates a SNMP packet
   """
   def __createSNMPPacket(self, dst, version, community):
      snmp = Snmp()
      snmp.dport   = self.dport;
      snmp.sport   = self.sport;
      snmp.timeout = self.timeout
      snmp.dst     = dst;
      snmp.version = version;
      snmp.community = community;
      return snmp

   """
   Go, go, go !
   """
   def run(self):
      # Retrieve arguments from command line
      self.parseArgs()
   
      # Creates the sync Queues
      q = Queue()
   
      # Creates a lock
      lock = Lock();

      # Creates a list of workerss
      workerList = []
      results = SnmpResults(lock)
      for worker in xrange(self.workersCount):
         worker = CheckCommunityStringWorker(q);
         worker.setResults(results);
         workerList.append(worker);
         worker.start();
   
      # Fills the synchronized queue with SNMP prepared packets
      for community in self.communityList:
         for dst in self.targetList:
            for version in self.versionList:
               snmp = self.__createSNMPPacket(dst, version, community);
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
      for worker in xrange(self.workersCount):
         worker = CheckCommunityTypeWorker(q);
         workerList.append(worker);
         worker.start();
    
      # Retrieve previously discovered snmp communities and check their types
      for dst, community, version in results:
         snmp = self.__createSNMPPacket(dst, version, community);
         q.put(snmp);
      # Wait for workers to end
      q.join();
   
      # Not sure if it is useful, but stops the workers
      for worker in workerList:
         worker.stop();
   
if( '__main__' == __name__ ):
   Main().run();

