import sys
import nids
import socket
import traceback
import logging.config
from struct import unpack

from ipwhois import IPWhois

from rudra.plugins.protoid import ProtoID
import rudra.libs.utils as utils
from rudra.external import utilitybelt


class PCAPAnalysis:
  def __init__(self, config={}):
    self.logger = logging.getLogger(__name__)

    self.config = config
    self.config['decodeprotolist'] = [
      'HTTP',
    ]
    self.report = {
      'flows': {},
      'hosts': {},
      'protocounts': {},
      'ctsbytescount': 0,
      'ctsbytesperpacket': 0,
      'ctspacketscount': 0,
      'stcbytescount': 0,
      'stcbytesperpacket': 0,
      'stcpacketscount': 0,
      'tcpbytescount': 0,
      'tcpbytesperpacket': 0,
      'tcppacketscount': 0,
      'tcpsessionscount': 0,
      'udpbytescount': 0,
      'udpbytesperpacket': 0,
      'udppacketscount': 0,
      'udpsessionscount': 0,
      'ippacketscount': 0
    }
    self.ipprotodict = {
      'icmp': 1,
      'igmp': 2,
      'tcp': 6,
      'igrp': 9,
      'udp': 17,
      'esp': 50,
      'ah': 51
    }


  def analyze(self, filename):
    self.logger.info('Invoking module for capinfos like pcap stats collection')
    pcapstats = utils.capinfos(filename)
    for k, v in pcapstats.iteritems():
      self.report[k] = v
    self.logger.info('Completed pcap stats collection')

    self.logger.debug('Initializing NIDS module for flow parsing')
    nids.param('pcap_filter', self.config['bpf']) # bpf
    nids.param('scan_num_hosts', 0) # disable portscan detection
    nids.param('pcap_timeout', 64) # ?
    nids.param('multiproc', True) # ?
    nids.param('tcp_workarounds', True) # ?
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksum verification
    nids.param('filename', filename)
    nids.init()

    nids.register_ip(self.handleIPStream)
    self.logger.debug('Registered IP packets handling callback')

    nids.register_udp(self.handleUDPStream)
    self.logger.debug('Registered UDP packets handling callback')

    nids.register_tcp(self.handleTCPStream)
    self.logger.debug('Registered TCP packets handling callback')

    try:
      self.logger.debug('Calling NIDS run() method for flow handling')
      nids.run()
    except Exception, e:
      self.logger.warning('Exception: %s' % (e))
      exc_type, exc_value, exc_traceback = sys.exc_info()
      traceback.print_exc()

    if (self.report['ctspacketscount'] or self.report['stcpacketscount'] or self.report['tcppacketscount'] or self.report['udppacketscount'])== 0:
      self.logger.error('NIDS failed to parse %s' % filename)
      return None

    else:
      if self.report['ctsbytescount'] > 0 and self.report['ctspacketscount'] > 0:
        self.report['ctsbytesperpacket'] = self.report['ctsbytescount'] / self.report['ctspacketscount']
        self.report['ctsbytescount'] = self.report['ctsbytescount']
      else:
        self.report['ctsbytesperpacket'] = 0
        self.report['ctsbytescount'] = 0

      if self.report['stcbytescount'] > 0 and self.report['stcpacketscount'] > 0:
        self.report['stcbytesperpacket'] = self.report['stcbytescount'] / self.report['stcpacketscount']
        self.report['stcbytescount'] = self.report['stcbytescount']
      else:
        self.report['stcbytesperpacket'] = 0
        self.report['stcbytescount'] = 0

      if self.report['tcpbytescount'] > 0 and self.report['tcppacketscount'] > 0:
        self.report['tcpbytesperpacket'] = self.report['tcpbytescount'] / self.report['tcppacketscount']
        self.report['tcpbytescount'] = self.report['tcpbytescount']
      else:
        self.report['tcpbytesperpacket'] = 0
        self.report['tcpbytescount'] = 0

      if self.report['udpbytescount'] > 0 and self.report['udppacketscount'] > 0:
        self.report['udpbytesperpacket'] = self.report['udpbytescount'] / self.report['udppacketscount']
        self.report['udpbytescount'] = self.report['udpbytescount']
      else:
        self.report['udpbytesperpacket'] = 0
        self.report['udpbytescount'] = 0

    self.logger.info('Completed flow parsing through NIDS module')
    return dict(self.report)


  def handleIPStream(self, pkt):
    self.report['ippacketscount'] += 1

    totalflows = 0
    for i in self.report['flows']:
      totalflows += 1

    iphdr = unpack('!BBHHHBBH4s4s', pkt[:20])
    ipversion = iphdr[0] >> 4
    ipihl = iphdr[0] & 0xF
    ipihl *= 4
    iptos = iphdr[1]
    iptotallen = iphdr[2]
    ipid = iphdr[3]
    ipttl = iphdr[5]
    ipproto = iphdr[6]
    ipsrc = socket.inet_ntoa(iphdr[8])
    ipdst = socket.inet_ntoa(iphdr[9])

    if ipproto == self.ipprotodict['tcp']:
      tcphdr = unpack('!HHLLBBHHH', pkt[ipihl:ipihl+20])
      tcpsport = tcphdr[0]
      tcpdport = tcphdr[1]
      tcpseq = tcphdr[2]
      tcpack = tcphdr[3]
      tcpoffset = tcphdr[4] >> 4
      tcphl = tcpoffset * 4
      tcpflags = tcphdr[5]
      tcpwindow = tcphdr[6]
      tcpchksum = tcphdr[7]
      tcpurgptr = tcphdr[8]

      data = pkt[ipihl+tcphl:]

      tcpflagsstr = []
      if tcpflags & 1 == 1: tcpflagsstr.append('F')
      if tcpflags & 2 == 2: tcpflagsstr.append('S')
      if tcpflags & 4 == 4: tcpflagsstr.append('R')
      if tcpflags & 8 == 8: tcpflagsstr.append('P')
      if tcpflags & 16 == 16: tcpflagsstr.append('A')
      if tcpflags & 32 == 32: tcpflagsstr.append('U')
      tcpflagsstr = "".join(tcpflagsstr)

      fivetuple = '%s:%s - %s:%s - TCP' % (ipsrc, tcpsport, ipdst, tcpdport)
      revfivetuple = '%s:%s - %s:%s - TCP' % (ipdst, tcpdport, ipsrc, tcpsport)

      if fivetuple not in self.report['flows'] and revfivetuple not in self.report['flows']:
        self.report['flows'][fivetuple] = {
          'id': totalflows+1,
          'info': {
            'ctsbuflen': None,
            'ipdst': None,
            'ipsrc': None,
            'proto': None,
            'stcbuflen': None,
            'tcpdport': None,
            'tcpsport': None
          },
          'transactions': None,
          'currtid': None
        }

        self.logger.debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (
          self.report['ippacketscount'],
          self.report['flows'][fivetuple]['id'],
          ipsrc,
          tcpsport,
          ipdst,
          tcpdport,
          tcpflagsstr,
          len(data)))

      else:
        if fivetuple in self.report['flows']:
          self.logger.debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (
            self.report['ippacketscount'],
            self.report['flows'][fivetuple]['id'],
            ipsrc,
            tcpsport,
            ipdst,
            tcpdport,
            tcpflagsstr,
            len(data)))

        elif revfivetuple in self.report['flows']:
          self.logger.debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (
            self.report['ippacketscount'],
            self.report['flows'][revfivetuple]['id'],
            ipsrc,
            tcpsport,
            ipdst,
            tcpdport,
            tcpflagsstr,
            len(data)))


    elif ipproto == self.ipprotodict['udp']:
      udphdr = unpack('!HHHH', pkt[ipihl:ipihl+8])
      udpsport = udphdr[0]
      udpdport = udphdr[1]
      udplen = udphdr[2]

      data = pkt[ipihl+8:]

      fivetuple = '%s:%s - %s:%s - UDP' % (ipsrc, udpsport, ipdst, udpdport)
      revfivetuple = '%s:%s - %s:%s - UDP' % (ipdst, udpdport, ipsrc, udpsport)

      if fivetuple not in self.report['flows'] and revfivetuple not in self.report['flows']:
        self.report['flows'][fivetuple] = {
          'id': totalflows+1,
          'info': {
            'ctsbuflen': None,
            'ipdst': None,
            'ipsrc': None,
            'proto': None,
            'stcbuflen': None,
            'tcpdport': None,
            'tcpsport': None
          }
        }

        self.logger.debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (
          self.report['ippacketscount'],
          self.report['flows'][fivetuple]['id'],
          ipsrc,
          udpsport,
          ipdst,
          udpdport,
          len(data)))

      else:
        if fivetuple in self.report['flows']:
          self.logger.debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (
            self.report['ippacketscount'],
            self.report['flows'][fivetuple]['id'],
            ipsrc,
            udpsport,
            ipdst,
            udpdport,
            len(data)))

        elif revfivetuple in self.report['flows']:
          self.logger.debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (
            self.report['ippacketscount'],
            self.report['flows'][revfivetuple]['id'],
            ipsrc,
            udpsport,
            ipdst,
            udpdport,
            len(data)))


  def handleUDPStream(self, addr, payload, pkt):
    ((ipsrc, udpsport), (ipdst, udpdport)) = addr
    fivetuple = '%s:%s - %s:%s - UDP' % (ipsrc, udpsport, ipdst, udpdport)
    revfivetuple = '%s:%s - %s:%s - UDP' % (ipdst, udpdport, ipsrc, udpsport)

    if fivetuple in self.report['flows']:
      tuplekey = fivetuple
    else:
      tuplekey = revfivetuple

    if ipsrc not in self.report['hosts'].keys():
      self.report['hosts'][ipsrc] = {
        'whois': None,
        'whois_text': None,
        'geo': None,
        'rdns': None
      }

      if not utilitybelt.is_rfc1918(ipsrc) and not utilitybelt.is_reserved(ipsrc):
        if self.config['enable_whois_lookup']:
          self.logger.debug('Invoking whois module for ipsrc %s' % ipsrc)
          ipwhois = IPWhois(ipsrc)
          try:
            self.report['hosts'][ipsrc]['whois'] = ipwhois.lookup()
            self.report['hosts'][ipsrc]['whois_text'] = ipwhois.get_whois()
          except:
            self.report['hosts'][ipsrc]['whois'] = None
            self.report['hosts'][ipsrc]['whois_text'] = None
        else:
          self.report['hosts'][ipsrc]['whois'] = None
          self.report['hosts'][ipsrc]['whois_text'] = None

        if self.config['enable_geoloc']:
          self.logger.debug('Invoking geoloc module for ipsrc %s' % ipsrc)
          try:
            self.report['hosts'][ipsrc]['geo'] = utilitybelt.ip_to_geo(ipsrc)
          except:
            self.report['hosts'][ipsrc]['geo'] = None
        else:
          self.report['hosts'][ipsrc]['geo'] = None

        if self.config['enable_reverse_dns']:
          try:
            self.logger.debug('Invoking reversedns lookup for ipsrc %s' % ipsrc)
            self.report['hosts'][ipsrc]['rdns'] = utilitybelt.reverse_dns_sna(ipsrc)
          except:
            self.report['hosts'][ipsrc]['rdns'] = None
        else:
          self.report['hosts'][ipsrc]['rdns'] = None

    if ipdst not in self.report['hosts'].keys():
      self.report['hosts'][ipdst] = {
        'whois': None,
        'whois_text': None,
        'geo': None,
        'rdns': None
      }

      if not utilitybelt.is_rfc1918(ipdst) and not utilitybelt.is_reserved(ipdst):
        if self.config['enable_whois_lookup']:
          self.logger.debug('Invoking whois module for ipdst %s' % ipdst)
          ipwhois = IPWhois(ipdst)

          try:
            self.report['hosts'][ipdst]['whois'] = ipwhois.lookup()
            self.report['hosts'][ipdst]['whois_text'] = ipwhois.get_whois()
          except:
            self.report['hosts'][ipdst]['whois'] = None
            self.report['hosts'][ipdst]['whois_text'] = None
        else:
          self.report['hosts'][ipdst]['whois'] = None
          self.report['hosts'][ipdst]['whois_text'] = None

        if self.config['enable_geoloc']:
          self.logger.debug('Invoking geoloc module for ipdst %s' % ipdst)
          try:
            self.report['hosts'][ipdst]['geo'] = utilitybelt.ip_to_geo(ipdst)
          except:
            self.report['hosts'][ipdst]['geo'] = None
        else:
          self.report['hosts'][ipdst]['geo'] = None

        if self.config['enable_reverse_dns']:
          try:
            self.logger.debug('Invoking reversedns lookup for ipdst %s' % ipdst)
            self.report['hosts'][ipdst]['rdns'] = utilitybelt.reverse_dns_sna(ipdst)
          except:
            self.report['hosts'][ipdst]['rdns'] = None
        else:
          self.report['hosts'][ipdst]['rdns'] = None

    if not self.report['flows'][tuplekey]['info']:
      self.report['flows'][tuplekey]['info'] = {
        'ipsrc': ipsrc,
        'udpsport': udpsport,
        'ipdst': ipdst,
        'udpdport': udpdport,
        'proto': None
      }

    if 'currtid' not in self.report['flows'][tuplekey].keys():
      self.report['flows'][tuplekey]['currtid'] = None

    # if first transaction for this session, init tid to 1
    if not self.report['flows'][tuplekey]['currtid']:
      self.report['flows'][tuplekey]['currtid'] = 1
      self.report['flows'][tuplekey]['transactions'] = {
        self.report['flows'][tuplekey]['currtid']: {
        'buf': None,
        'decode': {},
        'bufcompressionratio': 0,
        'bufentropy': 0,
        'buflen': 0,
        'bufmindatasize': 0,
        }
      }

    # else increment tid
    else:
      self.report['flows'][tuplekey]['currtid'] += 1
      self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']] = {
        'buf': None,
        'decode': {},
        'bufcompressionratio': 0,
        'bufentropy': 0,
        'buflen': 0,
        'bufmindatasize': 0,
      }

    self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']]['buf'] = payload[0:len(payload)]
    self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']]['buflen'] += len(payload)
    self.report['udppacketscount'] += 1
    self.report['udpbytescount'] += len(payload)

    if self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']]['buflen'] > 0:
      # if proto for this session is unknown and we have data
      if not self.report['flows'][tuplekey]['info']['proto']:
        self.logger.debug('[IP#%d.UDP#%d] Invoking protocol identification upon data (%s)' % (
          self.report['ippacketscount'],
          self.report['flows'][tuplekey]['id'],
          utils.size_string(self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']]['buflen'])))

        self.report['flows'][tuplekey]['info']['proto'] = ProtoID().identify(udpbuf=self.report['flows'][tuplekey]['transactions'][self.report['flows'][tuplekey]['currtid']]['buf'], tcpport=udpdport)


  def handleTCPStream(self, tcp):
    ((ipsrc, tcpsport), (ipdst, tcpdport)) = tcp.addr
    fivetuple = '%s:%s - %s:%s - TCP' % (ipsrc, tcpsport, ipdst, tcpdport)
    revfivetuple = '%s:%s - %s:%s - TCP' % (ipdst, tcpdport, ipsrc, tcpsport)

    if fivetuple in self.report['flows']:
      tuplekey = fivetuple
    else:
      tuplekey = revfivetuple

    if tcp.nids_state == nids.NIDS_JUST_EST:
      tcp.server.collect = 1
      tcp.client.collect = 1

      self.report['tcpsessionscount'] += 1

      if ipsrc not in self.report['hosts'].keys():
        self.report['hosts'][ipsrc] = {
          'whois': None,
          'whois_text': None,
          'geo': None,
          'rdns': None
        }

        if not utilitybelt.is_rfc1918(ipsrc) and not utilitybelt.is_reserved(ipsrc):
          if self.config['enable_whois_lookup']:
            self.logger.debug('Invoking whois module for ipsrc %s' % ipsrc)
            ipwhois = IPWhois(ipsrc)

            try:
              self.report['hosts'][ipsrc]['whois'] = ipwhois.lookup()
              self.report['hosts'][ipsrc]['whois_text'] = ipwhois.get_whois()
            except:
              self.report['hosts'][ipsrc]['whois'] = None
              self.report['hosts'][ipsrc]['whois_text'] = None
          else:
            self.report['hosts'][ipsrc]['whois'] = None
            self.report['hosts'][ipsrc]['whois_text'] = None

          if self.config['enable_geoloc']:
            self.logger.debug('Invoking geoloc module for ipsrc %s' % ipsrc)
            try:
              self.report['hosts'][ipsrc]['geo'] = utilitybelt.ip_to_geo(ipsrc)
            except:
              self.report['hosts'][ipsrc]['geo'] = None
          else:
            self.report['hosts'][ipsrc]['geo'] = None

          if self.config['enable_reverse_dns']:
            try:
              self.logger.debug('Invoking reversedns lookup for ipdst %s' % ipsrc)
              self.report['hosts'][ipsrc]['rdns'] = utilitybelt.reverse_dns_sna(ipsrc)
            except:
              self.report['hosts'][ipsrc]['rdns'] = None
          else:
            self.report['hosts'][ipsrc]['rdns'] = None

      if ipdst not in self.report['hosts'].keys():
        self.report['hosts'][ipdst] = {
          'whois': None,
          'whois_text': None,
          'geo': None,
          'rdns': None
        }

        if not utilitybelt.is_rfc1918(ipdst) and not utilitybelt.is_reserved(ipdst):
          if self.config['enable_whois_lookup']:
            self.logger.debug('Invoking whois module for ipdst %s' % ipdst)
            ipwhois = IPWhois(ipdst)

            try:
              self.report['hosts'][ipdst]['whois'] = ipwhois.lookup()
              self.report['hosts'][ipdst]['whois_text'] = ipwhois.get_whois()
            except:
              self.report['hosts'][ipdst]['whois'] = None
              self.report['hosts'][ipdst]['whois_text'] = None
          else:
            self.report['hosts'][ipdst]['whois'] = None
            self.report['hosts'][ipdst]['whois_text'] = None

          if self.config['enable_geoloc']:
            self.logger.debug('Invoking geoloc module for ipdst %s' % ipdst)
            try:
              self.report['hosts'][ipdst]['geo'] = utilitybelt.ip_to_geo(ipdst)
            except:
              self.report['hosts'][ipdst]['geo'] = None
          else:
            self.report['hosts'][ipdst]['geo'] = None

        if self.config['enable_reverse_dns']:
          try:
            self.logger.debug('Invoking reversedns lookup for ipdst %s' % ipdst)
            self.report['hosts'][ipdst]['rdns'] = utilitybelt.reverse_dns_sna(ipdst)
          except:
            self.report['hosts'][ipdst]['rdns'] = None
        else:
          self.report['hosts'][ipdst]['rdns'] = None

      self.report['flows'][tuplekey]['info'] = {
        'ipsrc': ipsrc,
        'tcpsport': tcpsport,
        'ipdst': ipdst,
        'tcpdport': tcpdport,
        'proto': None,
        'ctsbuflen': 0,
        'stcbuflen': 0,
      }

    elif tcp.nids_state == nids.NIDS_DATA:
      tcp.discard(0)

      # process CTS request
      if tcp.server.count_new > 0:
        self.report['flows'][tuplekey]['ctsbuf'] = tcp.server.data[0:tcp.server.count]
        self.report['flows'][tuplekey]['info']['ctsbuflen'] = len(self.report['flows'][tuplekey]['ctsbuf'])
        self.report['ctspacketscount'] += 1
        self.report['ctsbytescount'] += tcp.server.count_new
        self.report['ctsbytesperpacket'] = self.report['ctsbytescount'] / self.report['ctspacketscount']
        self.report['tcppacketscount'] += 1
        self.report['tcpbytescount'] += tcp.server.count_new

        #print 'ctsbuflen: %s' % self.report['flows'][tuplekey]['info']['ctsbuflen']
        #print 'ctspacketscount: %s' % self.report['ctspacketscount']
        #print 'ctsbytescount: %s' % self.report['ctsbytescount']
        #print 'ctsbytesperpacket: %s' % self.report['ctsbytesperpacket']
        #print 'tcppacketscount: %s' % self.report['tcppacketscount']
        #print 'tcpbytescount: %s' % self.report['tcpbytescount']

        if self.report['flows'][tuplekey]['info']['ctsbuflen'] > 0:
          # if proto for this session is unknown and we have data
          if not self.report['flows'][tuplekey]['info']['proto']:
            self.logger.debug('[IP#%d.TCP#%d] Invoking protocol identification upon CTS data (%s)' % (
              self.report['ippacketscount'],
              self.report['flows'][tuplekey]['id'],
              utils.size_string(self.report['flows'][tuplekey]['info']['ctsbuflen'])))

            self.report['flows'][tuplekey]['info']['proto'] = ProtoID().identify(ctsbuf=self.report['flows'][tuplekey]['ctsbuf'], tcpport=tcpdport)

          # else skip protoid and continue
          else:
            self.logger.debug('[IP#%d.TCP#%d] Received %s of %s CTS data (Total: %s)' % (
              self.report['ippacketscount'],
              self.report['flows'][tuplekey]['id'],
              utils.size_string(tcp.server.count_new),
              self.report['flows'][tuplekey]['info']['proto'],
              utils.size_string(self.report['flows'][tuplekey]['info']['ctsbuflen'])))

      # process STC request
      if tcp.client.count_new > 0:
        self.report['flows'][tuplekey]['stcbuf'] = tcp.client.data[0:tcp.client.count]
        self.report['flows'][tuplekey]['info']['stcbuflen'] = len(self.report['flows'][tuplekey]['stcbuf'])
        self.report['stcpacketscount'] += 1
        self.report['stcbytescount'] += tcp.client.count_new
        self.report['stcbytesperpacket'] = self.report['stcbytescount'] / self.report['stcpacketscount']
        self.report['tcppacketscount'] += 1
        self.report['tcpbytescount'] += tcp.client.count_new

        #print 'stcbuflen: %s' % self.report['flows'][tuplekey]['info']['stcbuflen']
        #print 'stcpacketscount: %s' % self.report['stcpacketscount']
        #print 'stcbytescount: %s' % self.report['stcbytescount']
        #print 'stcbytesperpacket: %s' % self.report['stcbytesperpacket']
        #print 'tcppacketscount: %s' % self.report['tcppacketscount']
        #print 'tcpbytescount: %s' % self.report['tcpbytescount']

        if self.report['flows'][tuplekey]['info']['stcbuflen'] > 0:
          # if proto for this session is unknown and we have data
          if not self.report['flows'][tuplekey]['info']['proto']:
            self.logger.debug('[IP#%d.TCP#%d] Invoking protocol identification upon STC data (%s)' % (
              self.report['ippacketscount'],
              self.report['flows'][tuplekey]['id'],
              utils.size_string(self.report['flows'][tuplekey]['info']['stcbuflen'])))

            self.report['flows'][tuplekey]['info']['proto'] = ProtoID().identify(stcbuf=self.report['flows'][tuplekey]['stcbuf'], tcpport=tcpdport)

          # else skip protoid and continue
          else:
            self.logger.debug('[IP#%d.TCP#%d] Received %s of %s STC data (Total: %s)' % (
              self.report['ippacketscount'],
              self.report['flows'][tuplekey]['id'],
              utils.size_string(tcp.client.count_new),
              self.report['flows'][tuplekey]['info']['proto'],
              utils.size_string(self.report['flows'][tuplekey]['info']['stcbuflen'])))

      self.report['tcpbytesperpacket'] = self.report['tcpbytescount'] / self.report['tcppacketscount']

    elif tcp.nids_state in (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET):
      self.logger.debug('Found TCP closing sequence for session %s' % tuplekey)
      tcp.server.collect = 0
      tcp.client.collect = 0
