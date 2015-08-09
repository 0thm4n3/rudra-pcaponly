import re
import logging.config

import rudra.libs.utils as utils


class ProtoDecode:
  def __init__(self, config={}):
    self.logger = logging.getLogger(__name__)

    self.config = config
    self.config['decode_regexes'] = {
      'HTTP': {
        'CTS': {
          'request': re.compile(r'^(?P<Request_Headers>.*?)\r*\n\r*\n(?P<Request_Data>.*)$', re.MULTILINE|re.DOTALL),
          'method_url_proto_ver': re.compile(r'(?P<Method>[\w]+)\s+(?P<URL>[^\s]+)\s+(?P<ProtoVer>HTTP/(?P<Ver>\d\.\d))', re.IGNORECASE),
          'host': re.compile(r'Host\s*:\s+(?P<Host>[^\r\n]+)', re.IGNORECASE),
          'referer': re.compile(r'Referer\s*:\s+(?P<Referer>[^\r\n]+)', re.IGNORECASE),
          'user_agent': re.compile(r'User-Agent\s*:\s+(?P<User_Agent>[^\r\n]+)', re.IGNORECASE),
          'cookie': re.compile(r'Cookie\s*:\s+(?P<Cookie>[^\r\n]+)', re.IGNORECASE),
          'content_type': re.compile(r'Content-Type\s*:\s+(?P<Content_Type>[^\r\n]+)', re.IGNORECASE),
          'content_length': re.compile(r'Content-Length\s*:\s+(?P<Content_Length>[^\r\n]+)', re.IGNORECASE),
          'content_encoding': re.compile(r'Content-Encoding\s*:\s+(?P<Content_Encoding>[^\r\n]+)', re.IGNORECASE),
          'transfer_encoding': re.compile(r'Transfer-Encoding\s*:\s+(?P<Transfer_Encoding>[^\r\n]+)', re.IGNORECASE),
          'connection': re.compile(r'Connection\s*:\s+(?P<Connection>[^\r\n]+)', re.IGNORECASE),
          'keep_alive': re.compile(r'Keep-Alive\s*:\s+(?P<Keep_Alive>[^\r\n]+)', re.IGNORECASE),
          #'accept': re.compile(r'Accept\s*:\s+(?P<Accept>[^\r\n]+)', re.IGNORECASE),
          #'accept_encoding': re.compile(r'Accept-Encoding\s*:\s+(?P<Accept_Encoding>[^\r\n]+)', re.IGNORECASE),
          #'range': re.compile(r'Range\s*:\s+(?P<value>[^\r\n]+)', re.IGNORECASE),
        },
        'STC': {
          'response': re.compile(r'^(?P<Response_Headers>.*?)\r*\n\r*\n(?P<Response_Data>.*)$', re.MULTILINE|re.DOTALL),
          'protover_code_msg': re.compile(r'(?P<ProtoVer>HTTP/(?P<Ver>\d\.\d))\s+(?P<Code>\d+)\s+(?P<Msg>[^\s]+)', re.IGNORECASE),
          'date': re.compile(r'Date\s*:\s+(?P<Date>[^\r\n]+)', re.IGNORECASE),
          'expires': re.compile(r'Expires\s*:\s+(?P<Expires>[^\r\n]+)', re.IGNORECASE),
          'content_type': re.compile(r'Content-Type\s*:\s+(?P<Content_Type>[^\r\n]+)', re.IGNORECASE),
          'content_length': re.compile(r'Content-Length\s*:\s+(?P<Content_Length>[^\r\n]+)', re.IGNORECASE),
          'content_disposition': re.compile(r'Content-Disposition\s*:\s+(?P<Content_Disposition>[^\r\n]+)', re.IGNORECASE),
          'content_transfer_encoding': re.compile(r'Content-Transfer-Encoding\s*:\s+(?P<Content_Transfer_Encoding>[^\r\n]+)', re.IGNORECASE),
          'content_encoding': re.compile(r'Content-Encoding\s*:\s+(?P<Content_Encoding>[^\r\n]+)', re.IGNORECASE),
          'transfer_encoding': re.compile(r'Transfer-Encoding\s*:\s+(?P<Transfer_Encoding>[^\r\n]+)', re.IGNORECASE),
          'server': re.compile(r'Server\s*:\s+(?P<Server>[^\r\n]+)', re.IGNORECASE),
          'connection': re.compile(r'Connection\s*:\s+(?P<Connection>[^\r\n]+)', re.IGNORECASE),
          'x_powered_by': re.compile(r'X-Powered-By\s*:\s+(?P<X_Powered_by>[^\r\n]+)', re.IGNORECASE),
        }
      },

      'IMAP': {
        'msgid': re.compile(r'Message-ID:[^\r\n]+', re.MULTILINE),
        'from': re.compile(r'From:[^\r\n]+', re.MULTILINE),
        'to': re.compile(r'To:[^\r\n]+', re.MULTILINE),
        'subject': re.compile(r'Subject:[^\r\n]+', re.MULTILINE)
      },

      'SMTP': {
        'helo': re.compile(r'HELO[^\r\n]+', re.MULTILINE),
        'ehlo': re.compile(r'EHLO[^\r\n]+', re.MULTILINE),
        'mailfrom': re.compile(r'MAIL FROM:[^\r\n]', re.MULTILINE),
        'rcptto': re.compile(r'RCPT TO:[^\r\n]', re.MULTILINE),
        'msgid': re.compile(r'Message-ID:[^\r\n]', re.MULTILINE),
        'from': re.compile(r'From:[^\r\n]+', re.MULTILINE),
        'to': re.compile(r'To:[^\r\n]+', re.MULTILINE),
        'subject': re.compile(r'Subject:[^\r\n]', re.MULTILINE)
      },

      'POP3': {
        'msgid': re.compile(r'Message-ID:[^\r\n]+', re.MULTILINE),
        'from': re.compile(r'From:[^\r\n]+', re.MULTILINE),
        'to': re.compile(r'To:[^\r\n]+', re.MULTILINE),
        'subject': re.compile(r'Subject:[^\r\n]+', re.MULTILINE)
      },
    }


  def http_transactions(self, report):
    for k in sorted(report['flows'].keys()):
      reqlist, reslist = [], []

      l4proto = k.split(' - ')[2]
      if report['flows'][k]['info'] and 'proto' in report['flows'][k]['info'] and report['flows'][k]['info']['proto']:
        l7proto = report['flows'][k]['info']['proto']
      else:
        l7proto = None

      if l4proto == 'TCP' and l7proto == 'HTTP':
        tmplist = []
        if 'ctsbuf' in report['flows'][k] and report['flows'][k]['ctsbuf']:
          tmplist = re.split(r'(GET|POST|HEAD|DELETE|PROPFIND)\s', report['flows'][k]['ctsbuf'])
          #print utils.hexdump(report['flows'][k]['ctsbuf'])
          for c, r in enumerate(tmplist):
            if r == '':
              continue
            if re.search(r'(GET|POST|HEAD|DELETE|PROPFIND)', r):
              reqlist.append('%s %s' % (tmplist[c], tmplist[c+1]))

        tmplist = []
        if 'stcbuf' in report['flows'][k] and report['flows'][k]['stcbuf']:
          tmplist = re.split(r'(HTTP/1\.1)', report['flows'][k]['stcbuf'])
          #print utils.hexdump(report['flows'][k]['stcbuf'])
          for c, r in enumerate(tmplist):
            if r == '':
              continue
            if re.search(r'(HTTP/1\.1)', r):
              reslist.append('%s %s' % (tmplist[c], tmplist[c+1]))

        #print
        #print k, len(reqlist), len(reslist)
        #print

        if (len(reqlist) == len(reslist)) and len(reqlist) > 1:
          for idx in range(len(reqlist) - 1):
            tid = idx + 1

            if not report['flows'][k]['transactions']:
              report['flows'][k]['transactions'] = {
                tid: {
                  'ctsbuf': '%s %s' % (reqlist[idx], reqlist[idx+1]),
                  'stcbuf': '%s %s' % (reslist[idx], reslist[idx+1]),
                  'ctsdecode': {},
                  'stcdecode': {},
                  'ctsbufcompressionratio': 0,
                  'stcbufcompressionratio': 0,
                  'ctsbufentropy': 0,
                  'stcbufentropy': 0,
                  'ctsbuflen': len('%s %s' % (reqlist[idx], reqlist[idx+1])),
                  'stcbuflen': len('%s %s' % (reslist[idx], reslist[idx+1])),
                  'ctsbufmindatasize': 0,
                  'stcbufmindatasize': 0
                }
              }
            else:
              report['flows'][k]['transactions'][tid] = {
                'ctsbuf': '%s %s' % (reqlist[idx], reqlist[idx+1]),
                'stcbuf': '%s %s' % (reslist[idx], reslist[idx+1]),
                'ctsdecode': {},
                'stcdecode': {},
                'ctsbufcompressionratio': 0,
                'stcbufcompressionratio': 0,
                'ctsbufentropy': 0,
                'stcbufentropy': 0,
                'ctsbuflen': len('%s %s' % (reqlist[idx], reqlist[idx+1])),
                'stcbuflen': len('%s %s' % (reslist[idx], reslist[idx+1])),
                'ctsbufmindatasize': 0,
                'stcbufmindatasize': 0
              }

        else:
          if 'ctsbuf' in report['flows'][k] and report['flows'][k]['ctsbuf']:
            ctsbuf = report['flows'][k]['ctsbuf']
            ctsbuflen = len(ctsbuf)
          else:
            ctsbuf = None
            ctsbuflen = 0

          if 'stcbuf' in report['flows'][k] and report['flows'][k]['stcbuf']:
            stcbuf = report['flows'][k]['stcbuf']
            stcbuflen = len(stcbuf)
          else:
            stcbuf = None
            stcbuflen = 0

          report['flows'][k]['transactions'] = {
            1: {
              'ctsbuf': ctsbuf,
              'stcbuf': stcbuf,
              'ctsdecode': {},
              'stcdecode': {},
              'ctsbufcompressionratio': 0,
              'stcbufcompressionratio': 0,
              'ctsbufentropy': 0,
              'stcbufentropy': 0,
              'ctsbuflen': ctsbuflen,
              'stcbuflen': stcbuflen,
              'ctsbufmindatasize': 0,
              'stcbufmindatasize': 0
            }
          }

      if l4proto == 'TCP' and l7proto != 'HTTP':
        if 'ctsbuf' in report['flows'][k] and report['flows'][k]['ctsbuf']:
          ctsbuf = report['flows'][k]['ctsbuf']
          ctsbuflen = len(ctsbuf)
        else:
          ctsbuf = None
          ctsbuflen = 0

        if 'stcbuf' in report['flows'][k] and report['flows'][k]['stcbuf']:
          stcbuf = report['flows'][k]['stcbuf']
          stcbuflen = len(stcbuf)
        else:
          stcbuf = None
          stcbuflen = 0

        report['flows'][k]['transactions'] = {
          1: {
            'ctsbuf': ctsbuf,
            'stcbuf': stcbuf,
            'ctsdecode': {},
            'stcdecode': {},
            'ctsbufcompressionratio': 0,
            'stcbufcompressionratio': 0,
            'ctsbufentropy': 0,
            'stcbufentropy': 0,
            'ctsbuflen': ctsbuflen,
            'stcbuflen': stcbuflen,
            'ctsbufmindatasize': 0,
            'stcbufmindatasize': 0
          }
        }

    return report


  def decode(self, report, filetype):
    for k in sorted(report['flows'].keys()):
      l4proto = k.split(' - ')[2]

      if 'currtid' in report['flows'][k].keys():
        del report['flows'][k]['currtid']

      if report['flows'][k]['info'] and report['flows'][k]['info']['proto']:
        l7proto = report['flows'][k]['info']['proto']
      else:
        l7proto = None

      if l4proto == 'TCP' and l7proto == 'HTTP' and 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
        for tid in sorted(report['flows'][k]['transactions'].keys()):
            ctsbuf = report['flows'][k]['transactions'][tid]['ctsbuf']
            stcbuf = report['flows'][k]['transactions'][tid]['stcbuf']

            ctsbuflen = len(ctsbuf) if ctsbuf else 0
            stcbuflen = len(stcbuf) if stcbuf else 0

            if (ctsbuflen or stcbuflen) > 0:
              self.logger.debug('Decoding CTS: %s and STC: %s buffers as HTTP' % (utils.size_string(ctsbuflen), utils.size_string(stcbuflen)))
              report['flows'][k]['transactions'][tid]['ctsdecode'], report['flows'][k]['transactions'][tid]['stcdecode'] = self.decodeAsHTTP(ctsbuf, stcbuf)

    return dict(report)


  def decodeAsHTTP(self, ctsbuf=None, stcbuf=None):
    decode = {'CTS': {},'STC': {}}
    matched = False

    if ctsbuf and len(ctsbuf) > 0:
      self.logger.debug("Decoding %s HTTP CTS buffer (RE Count: %d)" % (utils.size_string(len(ctsbuf)), len(self.config['decode_regexes']['HTTP']['CTS'])))

      matchcount = 0
      for regex_type, regex in self.config['decode_regexes']['HTTP']['CTS'].iteritems():
        for m in regex.finditer(ctsbuf):
          matched = True
          matchcount += 1

          for key, value in m.groupdict().iteritems():
            decode['CTS']['%s' % (key.replace('-', '_'))] = value

      if matched:
        self.logger.debug("Found %d HTTP decode matches for HTTP CTS buffer" % (matchcount))

        if 'Request_Data' in decode['CTS'].keys() and 'Transfer_Encoding' in decode['CTS'].keys():
          if decode['CTS']['Transfer_Encoding'] == 'chunked':
            if 'Request_Data' in decode['CTS'].keys():
              predechunksize = len(decode['CTS']['Request_Data'])
              decode['CTS']['Request_Data'] = utils.remove_chunked(decode['CTS']['Request_Data'])
              postdechunksize = len(decode['CTS']['Request_Data'])
              self.logger.debug("Dechunked %dB HTTP CTS buffer to %dB" % (predechunksize, postdechunksize))

        if 'Request_Data' in decode['CTS'].keys() and 'Content_Encoding' in decode['CTS'].keys():
          if 'gzip' in decode['CTS']['Content_Encoding']:
            if 'Request_Data' in decode['CTS'].keys():
              preungzipsize = len(decode['CTS']['Request_Data'])
              decode['CTS']['Request_Data'] = utils.expand_gzip(decode['CTS']['Request_Data'])
              postungzipsize = len(decode['CTS']['Request_Data'])
              self.logger.debug("Expanded gzipped %dB HTTP CTS buffer to %dB" % (preungzipsize, postungzipsize))

          if 'deflate' in decode['CTS']['Content_Encoding']:
            if 'Request_Data' in decode['CTS'].keys():
              preundeflatesize = len(decode['CTS']['Request_Data'])
              decode['CTS']['Request_Data'] = utils.expand_deflate(decode['CTS']['Request_Data'])
              postundeflatesize = len(decode['CTS']['Request_Data'])
              self.logger.debug("Expanded deflated %dB HTTP CTS buffer to %dB" % (preundeflatesize, postundeflatesize))

      else:
        self.logger.debug("Could not decode %s buffer since none of the %d HTTP CTS regexes matched" % (utils.size_string(len(ctsbuf)), len(self.config['decode_regexes']['HTTP']['CTS'])))

    if stcbuf and len(stcbuf) > 0:
      self.logger.debug("Decoding %s HTTP STC buffer (RE Count: %d)" % (utils.size_string(len(stcbuf)), len(self.config['decode_regexes']['HTTP']['STC'])))

      matchcount = 0
      for regex_type, regex in self.config['decode_regexes']['HTTP']['STC'].iteritems():
        for m in regex.finditer(stcbuf):
          matched = True
          matchcount += 1

          for key, value in m.groupdict().iteritems():
            decode['STC']['%s' % (key.replace('-', '_'))] = value

      if matched:
        self.logger.debug("Found %d HTTP decode matches for HTTP STC buffer" % (matchcount))

        if 'Response_Data' in decode['STC'].keys() and 'Transfer_Encoding' in decode['STC'].keys():
          if 'chunked' in decode['STC']['Transfer_Encoding']:
            if 'Response_Data' in decode['STC'].keys():
              predechunksize = len(decode['STC']['Response_Data'])
              decode['STC']['Response_Data'] = utils.remove_chunked(decode['STC']['Response_Data'])
              postdechunksize = len(decode['STC']['Response_Data'])
              self.logger.debug("Dechunked %dB HTTP STC buffer to %dB" % (predechunksize, postdechunksize))

        if 'Response_Data' in decode['STC'].keys() and 'Content_Encoding' in decode['STC'].keys():
          if 'gzip' in decode['STC']['Content_Encoding']:
            if 'Response_Data' in decode['STC'].keys():
              preungzipsize = len(decode['STC']['Response_Data'])
              decode['STC']['Response_Data'] = utils.expand_gzip(decode['STC']['Response_Data'])
              postungzipsize = len(decode['STC']['Response_Data'])
              self.logger.debug("Expanded gzipped %dB HTTP STC buffer to %dB" % (preungzipsize, postungzipsize))

          if 'deflate' in decode['STC']['Content_Encoding']:
            if 'Response_Data' in decode['STC'].keys():
              preundeflatesize = len(decode['STC']['Response_Data'])
              decode['STC']['Response_Data'] = utils.expand_deflate(decode['STC']['Response_Data'])
              postundeflatesize = len(decode['STC']['Response_Data'])
              self.logger.debug("Expanded deflated %dB HTTP STC buffer to %dB" % (preundeflatesize, postundeflatesize))

      else:
        self.logger.debug("Could not decode %s buffer since none of the %d HTTP STC regexes matched" % (utils.size_string(len(stcbuf)), len(self.config['decode_regexes']['HTTP']['STC'])))

    return decode['CTS'], decode['STC']

