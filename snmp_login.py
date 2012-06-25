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
   * Implement doHelp function
   * Implement get-next support for v2c
"""

# Suppress scapy complaints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import string, random
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

class Worker(Thread):
   def __init__(self, queue):
      Thread.__init__(self);
      self.__queue = queue;
      self.daemon = True;
      self.__doStop = False;

   def setFunction(self, function):
      if( 'checkCommunityString' == function ):
         self.__function = self.checkCommunityString;
      elif( 'checkCommunityType' == function ):
         self.__function = self.checkCommunityType;

   def setLock(self, lock):
      self.__lock = lock;

   def setResults(self, results):
      self.__results = results;

   def checkCommunityString(self, snmp):
      if( snmp.get(versionOid) and 0 == snmp.error() ):
         version = '1'
         if snmp.version == 1:
            version = '2c'
         print '[+] Community %s, version %s, for %s: "%s"' % (snmp.community, version, snmp.dst, snmp.response());
         self.__lock.acquire()
         self.__results.add(snmp.dst, snmp.version, snmp.community);
         self.__lock.release()

   def checkCommunityType(self, snmp):
      if( snmp.get(nameOid) and not snmp.error() ):
         name = snmp.response();
         if( snmp.set(nameOid, name) ):
            version = '1'
            if snmp.version == 1:
               version = '2c'
            if( not snmp.error() ):
               access = 'RW';
               #self.lock.acquire()
               #self.lock.release()
            else:
               access = 'RO';
               #self.lock.acquire()
               #self.lock.release()
            print '[+] Community %s, version %s, for %s is %s' % (community, version, dst, access);
         else:
            print '[!] Something went wrong...'

   def run(self):
      self.__doStop = False;
      while not self.__doStop:
         snmp = self.__queue.get()
         self.__function(snmp)
         self.__queue.task_done()

   def stop(self):
      self.__doStop = True;

# The ugly code :p
class SnmpResults:
   def __init__(self):
      self.__rslt = {};

   def add(self, dst, snmpVersion, communityName):
      if( not self.__rslt.has_key(dst) ):
         self.__rslt[dst] = {};
      if( not self.__rslt[dst].has_key(communityName) ):
         self.__rslt[dst][communityName] = []
      self.__rslt[dst][communityName].append(snmpVersion);

   def set(self, dst, snmpVersion, communityName, accessType):
      pass

   def __iter__(self):
      return SnmpResultsIter(self.__rslt);

# The ugliest code ever :p
class SnmpResultsIter:
   def __init__(self, rslt):
      self.rslt = rslt;
      self.done = False
      self.start =True;
   def next(self):
      if self.done : 
         raise StopIteration
      elif self.start:
         self.itr = self.rslt.__iter__();
         self.dst = self.itr.next()
         self.cItr = self.rslt[self.dst].__iter__();
         self.community = self.cItr.next();
         self.vItr = self.rslt[self.dst][self.community].__iter__()
         self.start = False
      try:
         self.version = self.vItr.next();
      except StopIteration:
         try:
            self.community = self.cItr.next();
            try:
               self.vItr = self.rslt[self.dst][self.community].__iter__();
               self.version = self.vItr.next();
            except Exception, e:
               print 'Something went wrong (%s)...' % str(e)
         except StopIteration:
            try:
               self.itr.next()
            except StopIteration:
               self.done = True;
            self.dst = self.itr.next()
            self.cItr = self.rslt[self.dst].__iter__();
            self.community = self.cItr.next();
            self.vItr = self.rslt[self.dst][self.community].__iter__()
            self.version = self.vItr.next()
      return self.dst, self.community, self.version;

def doHelp():
   print 'Sorry, no help implemented yet ...'

def parseArgs():
   communityList = ['public', 'private']
   output        = sys.stdout;
   stopOnFirst   = False
   versionList   = [0, 1]
   dport = 161
   sport = None
   try:
      opts, targetList = getopt(sys.argv[1:], 'c:C:d:s:o:v:fh', ['community=', 'communityFile=', 'dport=', 'sport=', 'output=', 'help']);
   except GetoptError, e:
      print '-E- %s' % str(e);
  
   for k, v in opts:
      if( '-c' == k or '--community' == k ):
         communityList = [v];
      elif( '-C' == k or '--communityFile' == k ):
         if( not os.path.exists(v) ):
            print '%s: no such file or directory' % (v)
            sys.exit(-1)
         communityList = open(v, 'r').read(-1).split('\n');
      elif( '-d' == k or '--dport' == k ):
         dport = int(v);
      elif( '-s' == k or '--sport' == k ):
         sport = int(v)
      elif( '-o' == k or '--output' == k ):
         if( os.path.exists(v) ):
            print '%s: file exists. Please use a different file name.' % (v)
            sys.exit(-1);
         output = open(v, 'w');
      elif( '-v' == k or '--version' == k ):
         versionList = [int(x) for x in v.split(',')];
      elif( '-f' == k ):
         stopOnFirst = True;
      elif( '-h' == k or '--help' == k ):
         doHelp();
         sys.exit(0)
   return targetList, communityList, output, stopOnFirst, dport, sport, versionList

if( "__main__" == __name__ ):
   workersCount=30
   targetList, communityList, output, stopOnFirst, dport, sport, versionList =  parseArgs()
   q = Queue()
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
   for community in communityList:
      for dst in targetList:
         for version in versionList:
            snmp = Snmp()
            snmp.dport = dport;
            snmp.sport = sport;
            snmp.dst = dst;
            snmp.version = version;
            snmp.community = community;
            q.put(snmp);
   # Wait for workers to end
   q.join();

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
 
   for dst, community, version in results:
      snmp = Snmp()
      snmp.dport = dport;
      snmp.sport = sport;
      snmp.dst = dst;
      snmp.version = version;
      snmp.community = community;
      q.put(snmp);
   # Wait for workers to end
   q.join();


#if( not found.has_key(dst) ):
#    found[dst] = []
#if( not community in found[dst] ):
#   found[dst].append((version, community))
#if( stopOnFirst ):
#   done = True
#break; # do not test further version
   
#   for dst, communityTupleList in found.items():
#      snmp.dst = dst;
#      # test write
#      for  version, community in communityTupleList:
#         snmp.community = community
#         snmp.version = version
#         if( snmp.get(nameOid) and not snmp.error() ):
#            name = snmp.response();
#            if( snmp.set(nameOid, name) ):
#               if( not snmp.error() ):
#                  print '[+] Community %s for %s is RW' % (community, dst);
#               else:
#                  print '[+] Community %s for %s is RO' % (community, dst);
#            else:
#               print '[!] Something went wrong...'

