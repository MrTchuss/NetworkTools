#!/usr/bin/env python

##############################################
# Nicolas Biscos - 20 May 12                 #
#                                            #
# Perform a dictionary-based SNMP community  #
# brute-force. This can be use as a lib for  # 
# get/set SNMP values                        #
#                                            #
##############################################

"""
TODO List:
   * Implement threading on host basis to improve performance
   * Implement output file
   * Implement doHelp function
   * Implement get-next support for v2c
"""

from scapy.all import *
import string, random
from getopt import getopt;
import threading

versionOid = '.1.3.6.1.2.1.1.1.0'
nameOid = '.1.3.6.1.2.1.1.5.0'

class SR(threading.Thread):
   def __init__(self, packet, timeout):
      threading.Thread.__init__(self);
      self.packet = packet;
      self.timeout = timeout;
      self.ans =None

   def getAns(self):
      return self.ans;

   def start(self):
      self.ans = sr1(self.packet, timeout=self.timeout);
      
   def stop(self):
      pass

class snmp:
   version = 0
   dport = 161
   timeout = 0.01
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

   def randomCommunity(self):
         self.community = ''.join([random.choice(string.ascii_uppercase) for x in range(8)])

   def randomSport(self):
      self.sport = RandInt()
      self.sport.max = 65535
      self.sport.min = 1024
   
   def error(self):
      return self.__error;

   def response(self):
      return self.__response;

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
      #sender = SR(packet, self.timeout)
      #sender.run()
      #ans = sender.getAns()
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
 
   def get(self, oid):
      pdu = SNMPget(varbindlist=SNMPvarbind(oid=oid));
      return self.__getset(pdu)
      
   def set(self, oid, value):
      pdu = SNMPset(varbindlist=SNMPvarbind(oid=oid, value=value))
      return self.__getset(pdu)

def doHelp():
   print 'Sorry, no help implemented yet ...'
if( "__main__" == __name__ ):
   communityList = ['public', 'private']
   output        = sys.stdout;
   stopOnFirst   = False
   versionList   = [0, 1]
   opts, targetList = getopt(sys.argv[1:], 'c:C:d:s:o:v:fh', ['community=', 'communityFile=', 'dport=', 'sport=', 'output=', 'help']);
  
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

   snmp = snmp()
   found = {}
   done = False
   for community in communityList:
      if done:
         break
      for dst in targetList:
         snmp.dst = dst;
         if done :
            break
         for version in versionList:
            snmp.version = version;
            snmp.community = community
            if( snmp.get(versionOid) and 0 == snmp.error() ):
               print '[+] Community %s for %s: "%s"' % (community, dst, snmp.response());
               if( not found.has_key(dst) ):
                  found[dst] = []
               if( not community in found[dst] ):
                  found[dst].append((version, community))
               if( stopOnFirst ):
                  done = True
               break; # do not test further version
   
   for dst, communityTupleList in found.items():
      snmp.dst = dst;
      # test write
      for  version, community in communityTupleList:
         snmp.community = community
         snmp.version = version
         if( snmp.get(nameOid) and not snmp.error() ):
            name = snmp.response();
            if( snmp.set(nameOid, name) ):
               if( not snmp.error() ):
                  print '[+] Community %s for %s is RW' % (community, dst);
               else:
                  print '[+] Community %s for %s is RO' % (community, dst);
            else:
               print '[!] Something went wrong...'
