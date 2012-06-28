#!/usr/bin/env python

##############################################
# Nicolas Biscos - 18 Apr 12                 #
#                                            #
# Scapy dissector for CDP                    #
# Implements a listener that shows crucial   #
# infos.                                     #
#                                            #
##############################################

"""
TODO List:
   * Implement specific dissectors for some TLV (e.g managment address, native VLAN, capability, etc.)
"""
 
# Suppress scapy complaints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from binascii import hexlify
from struct import unpack
from getopt import getopt
from getopt import GetoptError

#class CDPFieldLenField(FieldLenField):
#   def m2i(self, pkt, s):
#      return int(hexlify(s), 16);
#
#   def getfield(self, pkt, s):
#      l = 4
#      if( pkt.content ):
#         l += len(pkt.content);
#      return s[4:], self.m2i(s[2:4]);

#class CDPStrLenField(StrLenField):
#   def getfield(self, pkt, s):
#      return s[pkt.len:], pkt.content;

class CDPTLV(Packet):
   fields_desc = [ShortEnumField('type', 0x00001,  # according to http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#xtocid12
                                 {  1: 'DeviceID',
                                    2: 'Version',
                                    3: 'PortID',
                                    4: 'Capability',
                                    5: 'SoftwareVersion',
                                    6: 'Platform',
                                    7: 'IPPrefix',
                                    8: 'Hello',
                                    9: 'VTPManagementDomain',
                                   10: 'NativeVLAN',
                                   11: 'Duplex',
                                 0x12: 'TrustBitmap',
                                 0x16: 'ManagementAddress'
                                 }),
                  FieldLenField('len', None, length_of='content', adjust=lambda pkt,x:x+4),
                  StrLenField('content', None, length_from=lambda pkt : pkt.len-4)];

class CDPPacketListField(PacketListField):
    def m2i(self, pkt, m):
       return CDPTLV(m);

    def getfield(self, pkt, s):
        lst = []
        ret = ""
        remain = s
        while remain:
            if(len(remain) >= 0x4) :
                l = int(hexlify(remain[2:4]), 16);
                remain,ret = remain[:l],remain[l:]
            else:
                remain, ret = None, remain
            try:
                p = self.m2i(pkt,remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = ""
            lst.append(p)
            remain = ret
        return remain+ret,lst
 

# taken from FX's code: ftp://ftp.ntua.gr/mirror/technotronic/routers-switches/cdp.c&sa=U&ei=_hyPT_eJBNKXhQfvrZCMCw&ved=0CCcQFjAH&usg=AFQjCNETbj1QdZ4D7rq_bpb66c4JZX71aA
def cdp_checksum(pkt):
   sum = 0;
   count = len(pkt)
   i=0
   while( count > 1 ):
      sum = sum + ord(pkt[i]);
      i += 1
      count -= 2;
   # Add left-over byte, if any
   if( count > 0 ):
      sum = sum + ((ord(pkt[i]) &0xFF)<<8);
   # Fold 32-bit sum to 16 bits
   while (sum>>16):
      sum = (sum & 0xffff) + (sum >> 16);
   sum = (~sum) & 0xffff
   return sum


class CDP(Packet):
   name = 'CDP'
   fields_desc = [ByteField('version', 2),
                 ByteField('ttl',180),
                 XShortField('chksum', None),
                 CDPPacketListField('infos', [], None)];
   def post_build(self, pkt, payload):
      Packet.post_build(self, pkt, payload);
      if( self.chksum == None ): # from /usr/share/pyshared/scapy/layers/inet.py
         # According to https://bugs.wireshark.org/bugzilla/attachment.cgi?id=2638
         s = pkt+payload
         if( len(s) % 2 == 1 ):
            s = s[:-1] + '\x00' + s[-1:]
         ck = checksum(s);
         #ck = cdp_checksum(pkt+payload);
         pkt = pkt[:2] + chr(ck>>8)+chr(ck&0xff)+pkt[4:];   # from /usr/share/pyshared/scapy/layers/inet.py
      return pkt+payload

# http://wiki.wireshark.org/CDP
bind_layers(SNAP, CDP, code=0x2000, OUI=0x00000C);
bind_layers(HDLC, CDP, control=0x2000);
bind_layers(PPP, CDP, proto=0x0207);

class CDPMain:
   def __init__(self):
      self.timeout=60;

   def doHelp(self):
      print """
CDP.py - Capture and dispay Cisco Discovery Protocol information

Syntax: ./CDP.py [-i iface]  [-t timeout] [-h]

   -h          Display this message and exits
   -i iface    interface to listen on
   -t timeout  listen for maximum timeout secs

"""

   def parseArgs(self):
      try:
         opts, garbage = getopt(sys.argv[1:], 't:i:h', ['timeout=', 'iface=', 'help']);
      except GetoptError, e:
         print '[!] %s' % str(e);
         sys.exit(-1);
      for k, v in opts:
         if( '-i' == k or '--iface' == k ):
            conf.iface = v;
         elif( '-t' == k or '--timeout' == k ):
            self.timeout=float(v);
         elif( '-h' == k or '--help' == k ):
            self.doHelp();
            sys.exit(0);
      if( 0 != len(garbage) ):
         print '[!] No options required';
         sys.exit(-1);
         
   def parse(self, p):
      for tlv in p[CDP].infos:
         if tlv.type == 10:
            print 'VLAN %d' % (unpack('!H', tlv.content)[0]);
         elif tlv.type == 3:
            print 'Port: %s' % tlv.content
         elif tlv.type == 1:
            print 'DeviceID: %s' % tlv.content
         elif tlv.type == 0x16:
            addrCount = unpack('!I', tlv.content[0:4])[0]
            raw = tlv.content[4:]
            for i in range(addrCount):
               addrLen = unpack('!H', raw[3:5])[0]
               addr = []
               for addrByteIdx in range(addrLen):
                  addr.append(unpack('!B', raw[5+addrByteIdx:5+addrByteIdx+1])[0])
               print 'Management Address: %s' % ('.'.join([str(x) for x in addr]))
               raw = raw[5+addrLen:]

   def run(self):
      self.parseArgs();
      if( 'posix' != os.name ):
         print '[!] Sorry, must run on Linux/Unix';
         sys.exit(-1);
      if( 0 != os.geteuid() ):
         print '[!] Must be root to run this script';
         sys.exit(-1);
      sniff(lfilter=lambda x:x.haslayer(CDP), count=1, timeout=self.timeout, prn=self.parse);

if( '__main__' == __name__ ):
   m = CDPMain();
   m.run();



