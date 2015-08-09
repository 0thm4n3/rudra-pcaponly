from __future__ import division

import os
import re
import sys
import json
import math
import time
import gzip
import zlib
import arrow
import magic
import base64
import pdfkit
import pickle
import pydeep
import shutil
import socket
import struct
import fnmatch
import hashlib
import unirest
import datetime
import collections

import colorsys
from PIL import Image, ImageDraw

try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO


def set_prompt(ps1='(rudra) ', ps2='... '):
  sys.ps1 = ps1
  sys.ps2 = ps2


# https://arcpy.wordpress.com/2012/04/20/146/
# start = time.time()
# end = time.time()
# sec_elapsed = end - start
def hms_string(sec_elapsed):
  h = int(sec_elapsed / (60 * 60))
  m = int((sec_elapsed % (60 * 60)) / 60)
  s = sec_elapsed % 60.

  return "{}:{:>02}:{:>05.2f}".format(h, m, s)


# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def find_files(search_dir='./', regex='*'):
  matches = []

  for root, dirnames, filenames in os.walk(search_dir):
    for filename in fnmatch.filter(filenames, regex):
      matches.append(os.path.join(root, filename))

  return matches


def is_dir(path):
  return os.path.isdir(path)


def file_size(filename):
  return os.stat(filename).st_size


def get_current_datetime():
  return time.strftime("%c")


def time_now(locale='Asia/Kolkata'):
  return arrow.utcnow().to(locale)


def time_now_json(locale='Asia/Kolkata'):
  return arrow.utcnow().to(locale).for_json()


def time_to_human(arrowtime, locale='Asia/Kolkata'):
  return arrowtime.to(locale).humanize()


# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def list_all_files(directory, pattern='*.*'):
  matches = []
  for root, dirnames, filenames in os.walk(directory):
    for filename in fnmatch.filter(filenames, pattern):
      if os.path.exists(os.path.join(root, filename)):
        matches.append(os.path.join(root, filename))

  return matches


def is_file(filename):
  return os.path.isfile(filename)


def file_size(filename):
  return os.stat(filename).st_size


def file_size_string(filename):
  return size_string(os.stat(filename).st_size)


def file_mimetype(filename):
  return magic.from_file(filename, mime=True)


def file_magic(filename):
  return magic.from_file(filename)


def buffer_mimetype(buf):
  return magic.from_buffer(buf, mime=True)


def buffer_magic(buf):
  return magic.from_buffer(buf)


def file_hashes(filename, algo='sha256', blocksize=65536):
  file_handle = open(filename, 'rb')
  buf = file_handle.read(blocksize)

  if algo == 'crc32':
    return "%X" % (zlib.crc32(open(filename,"rb").read()) & 0xffffffff)
  elif algo == 'adler32':
    return "%X" % (zlib.adler32(open(filename,"rb").read()) & 0xffffffff)
  elif algo == 'md5':
    hasher = hashlib.md5()
  elif algo == 'sha1':
    hasher = hashlib.sha1()
  elif algo == 'sha224':
    hasher = hashlib.sha224()
  elif algo == 'sha256':
    hasher = hashlib.sha256()
  elif algo == 'sha384':
    hasher = hashlib.sha384()
  elif algo == 'sha512':
    hasher = hashlib.sha512()
  elif algo == 'ssdeep':
    return pydeep.hash_file(filename)
  else:
    return None

  while len(buf) > 0:
    hasher.update(buf)
    buf = file_handle.read(blocksize)
  return hasher.hexdigest()


def buf_hashes(buf, algo='sha256'):
  if not buf:
    return None

  if algo == 'crc32':
    return "%X" % (zlib.crc32(buf) & 0xffffffff)
  elif algo == 'adler32':
    return "%X" % (zlib.adler32(buf) & 0xffffffff)
  elif algo == 'md5':
    hasher = hashlib.md5()
  elif algo == 'sha1':
    hasher = hashlib.sha1()
  elif algo == 'sha224':
    hasher = hashlib.sha224()
  elif algo == 'sha256':
    hasher = hashlib.sha256()
  elif algo == 'sha384':
    hasher = hashlib.sha384()
  elif algo == 'sha512':
    hasher = hashlib.sha512()
  elif algo == 'ssdeep':
    return pydeep.hash_file(filename)
  else:
    return None

  hasher.update(buf)
  return hasher.hexdigest()


def data_to_qrcode(data, destfile='./qr.png'):
  qr = qrtools.QR(data=data)
  qr.encode()
  tmpfile = qr.get_tmp_file()
  if is_file(tmpfile) and not is_file(destfile):
    shutil.move(tmpfile, destfile)


def qrcode_to_data(imgfile):
  qr = qrtools.QR()
  qr.decode(imgfile)
  return qr.data


def datetime_current():
  return datetime.datetime.utcnow()


def datetime_current_str():
  return "%s %s" % (datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f"), time.tzname[0])


def get_regex_pattern(regexobj):
  return regexobj.pattern

  dumps = pickle.dumps(regexobj)
  regexpattern = re.search("\n\(S'(.*)'\n", dumps).group(1)
  if re.findall(r'\\x[0-9a-f]{2}', regexpattern):
    regexpattern = re.sub(r'(\\x)([0-9a-f]{2})', r'x\2', regexpattern)

  return regexpattern


# ascii printable filter for raw bytes
def printable(data):
  return ''.join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
                  or ord(ch) == 9
                  or ord(ch) == 10
                  or ord(ch) == 13
                  or ord(ch) == 32])


def hexdump(data, dataoffset=0, length=16, sep='.'):
  lines = []
  FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
  for c in xrange(0, len(data), length):
    chars = data[c:c+length]
    hex = ' '.join(["%02x" % ord(x) for x in chars])
    printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
    lines.append("%08x:  %-*s  |%s|\n" % (c+dataoffset, length*3, hex, printablechars))

  return ''.join(lines)


def size_string(bytes, precision=1):
  # http://code.activestate.com/recipes/577081-humanized-representation-of-a-number-of-bytes/
  abbrevs = (
    (1<<50L, 'PB'),
    (1<<40L, 'TB'),
    (1<<30L, 'GB'),
    (1<<20L, 'MB'),
    (1<<10L, 'KB'),
    (1, 'B')
  )

  if bytes == 1:
    return '1B'

  for factor, suffix in abbrevs:
    if bytes >= factor:
      break

  return ('%.*f%s' % (precision, bytes / factor, suffix)).replace(".0", "")


def to_base64(data):
  if data:
    return base64.b64encode(data)
  else:
    return data


def from_base64(data):
  if data:
    return base64.b64decode(data)
  else:
    return data


def dict_print(dictdata):
  sd = collections.OrderedDict(sorted(dictdata.items()))
  print json.dumps(sd, indent=4)


# calculate the frequency of each byte value in the file
# http://www.kennethghartman.com/calculate-file-entropy/
def get_freq_list(byteArr):
  sizeinbytes = len(byteArr)
  freqList = []

  for b in range(256):
    ctr = 0
    for byte in byteArr:
      if byte == b:
        ctr += 1
    freqList.append(float('%.6f' % (float(ctr) / sizeinbytes)))

  return freqList


# calculate entropy of a file
# http://www.kennethghartman.com/calculate-file-entropy/
def entropy_compression_stats(filename, precision=2):
  file_handle = open(filename, 'rb')

  # read the whole file into a byte array
  byteArr = map(ord, file_handle.read())
  file_handle.close()
  filesizeinbytes = len(byteArr)
  freqList = get_freq_list(byteArr)

  # shannon entropy
  ent = 0.0
  for freq in freqList:
    if freq > 0:
      ent = ent + freq * math.log(freq, 2)
  ent = -ent

  # minimum possible filesize after compression
  minfilesize = (ent * filesizeinbytes) / 8

  # compression efficiency
  sizediff = filesizeinbytes - minfilesize
  if sizediff > 0:
    compressionratio = (sizediff / filesizeinbytes) * 100
  else:
    compressionratio = 0

  return dict({
    'bytefreqlist': freqList,
    'filesizeinbytes': filesizeinbytes,
    'shannonentropy': '{0:.2f}'.format(ent),
    'minfilesize': '{0:.2f}'.format(minfilesize),
    'compressionratio': '{0:.2f}'.format(compressionratio)
  })


def entropy_compression_stats_buf(data):
  # map the data into a byte array
  byteArr = map(ord, data)
  datasizeinbytes = len(byteArr)
  freqList = get_freq_list(byteArr)

  # shannon entropy
  ent = 0.0
  for freq in freqList:
    if freq > 0:
      ent = ent + freq * math.log(freq, 2)
  ent = -ent

  # minimum possible filesize after compression
  mindatasize = (ent * datasizeinbytes) / 8

  # compression efficiency
  sizediff = datasizeinbytes - mindatasize
  compressionratio = (sizediff / datasizeinbytes) * 100 if sizediff > 0 else 0

  return dict({
    'bytefreqlist': freqList,
    'datasizeinbytes': datasizeinbytes,
    'shannonentropy': '{0:.2f}'.format(ent),
    'mindatasize': '{0:.2f}'.format(mindatasize),
    'compressionratio': '{0:.2f}'.format(compressionratio)
  })


# Inspired from jsunpack, slightly modified
def remove_chunked(chunk_data):
  try:
    data = chunk_data
    decoded = ''
    chunk_pos = data.find('\n')+1
    chunk_length = int('0x'+data[:chunk_pos], 0)

    while(chunk_length > 0):
      decoded += data[chunk_pos:chunk_length+chunk_pos]
      data = data[chunk_pos+chunk_length+2:] # +2 skips \r\n
      chunk_pos = data.find('\n')+1

      if chunk_pos <= 0:
        break

      chunk_length = int('0x'+data[:chunk_pos], 0)

    return decoded

  except:
    print '[!] Exception while dechunking. Returning %dB data as-is.' % (len(chunk_data))
    return chunk_data


def expand_gzip(gzip_data):
  try:
    # http://stackoverflow.com/questions/2695152/in-python-how-do-i-decode-gzip-encoding
    return zlib.decompress(gzip_data, 16+zlib.MAX_WBITS)

  except Exception, ex:
    print ex
    print '[!] Exception while expanding gzip data. Returning %dB data as-is.' % (len(gzip_data))
    return gzip_data


def expand_deflate(deflate_data):
  try:
    # http://love-python.blogspot.in/2008/07/accept-encoding-gzip-to-make-your.html
    return zlib.decompress(deflate_data)

  except:
    print '[!] Exception while expanding defalte data. Returning %dB data as-is.' % (len(deflate_data))
    return deflate_data


# referenced from https://code.google.com/p/dpkt/source/browse/trunk/dpkt/pcap.py
datalink_types = {
  0: 'DLT_NULL',
  1: 'DLT_EN10MB',
  2: 'DLT_EN3MB',
  3: 'DLT_AX25',
  4: 'DLT_PRONET',
  5: 'DLT_CHAOS',
  6: 'DLT_IEEE802',
  7: 'DLT_ARCNET',
  8: 'DLT_SLIP',
  9: 'DLT_PPP',
  10: 'DLT_FDDI',
  18: 'DLT_PFSYNC',
  105: 'DLT_IEEE802_11',
  113: 'DLT_LINUX_SLL',
  117: 'DLT_PFLOG',
  127: 'DLT_IEEE802_11_RADIO'
}


# generates wireshark's capinfos like stats
# needs additional testing
def capinfos(filename):
  if is_file(filename):
    file_handle = open(filename, 'rb')
    buf = file_handle.read()
    pcapstats = dict()
    endianness = None

    # extract pcap magic using host's native endianess
    (pcap_magic, ) = struct.unpack('=I', buf[:4])

    # if the pcap is LE
    if pcap_magic == 0xa1b2c3d4:
      (pcap_magic, pcap_version_major, pcap_version_minor, pcap_thiszone, pcap_sigfigs, pcap_snaplen, pcap_network) = struct.unpack('<IHHIIII', buf[:24])
      endianness = 'LITTLE'

    # if the pcap is BE
    elif pcap_magic == 0xd4c3b2a1:
      (pcap_magic, pcap_version_major, pcap_version_minor, pcap_thiszone, pcap_sigfigs, pcap_snaplen, pcap_network) = struct.unpack('>IHHIIII', buf[:24])
      endianness = 'BIG'

    # for pcaps which are something else (0x4d3c2b1a)?
    else:
      return pcapstats

    starttime = None
    endtime = None
    s = 24
    e = s + 16
    packetscount = 0
    bytescount = 0
    while True:
      if endianness is 'LITTLE':
        (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack('<IIII', buf[s:e])
      elif endianness is 'BIG':
        (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack('>IIII', buf[s:e])

      packetscount += 1
      bytescount += incl_len

      if not starttime:
        starttime = datetime.datetime.fromtimestamp(ts_sec)
        bytescount += incl_len

      endtime = datetime.datetime.fromtimestamp(ts_sec)

      s = e + incl_len
      e = s + 16

      if e > len(buf):
        break

    totsecs = int((endtime - starttime).total_seconds())
    if totsecs < 1:
      totsecs = 1
    pcapstats['totsecs'] = totsecs

    pcapstats['pcapmagic'] = '0x%08X' % pcap_magic
    pcapstats['version_major'] = pcap_version_major
    pcapstats['version_minor'] = pcap_version_minor
    pcapstats['snaplen'] = pcap_snaplen
    pcapstats['pcapencapsulation'] = datalink_types[pcap_network]

    pcapstats['packetscount'] = packetscount
    pcapstats['bytescount'] = bytescount

    pcapstats['capturestarttime'] = starttime.strftime('%c')
    pcapstats['captureendtime'] = endtime.strftime('%c')
    pcapstats['captureduration'] = (endtime - starttime).total_seconds()

    byterate = (bytescount / totsecs) if totsecs > 0 else bytescount
    bitrate = ((bytescount * 8) / totsecs) if totsecs > 0 else (bytescount * 8)
    pcapstats['byterate'] = '{0:.2f}'.format(byterate)
    pcapstats['bitrate'] = '{0:.2f}'.format(bitrate)

    avgpacketsize = (bytescount / packetscount) if packetscount > 0 else bytescount
    avgpacketrate = (packetscount / totsecs) if totsecs > 0 else packetscount
    pcapstats['avgpacketsize'] = '{0:.2f}'.format(avgpacketsize)
    pcapstats['avgpacketrate'] = '{0:.2f}'.format(avgpacketrate)

    return dict(pcapstats)


# https://github.com/Xen0ph0n/XRayGlasses
# todo: add support for other image types
# todo: use PIL or something else to get rid of manually crafting images
def buf_to_bmpimage(buf):
  outbuf = None
  b = bytearray(buf)

  # pad the end of the byte array so the length is a multiple of 256
  if len(b) % 256 > 0:
    remainder = len(b) % 256
    padding = 256 - remainder
    for i in range(padding):
      b.append(0x00)

  # start writing the static BMP header
  outbuf = "\x42\x4d\x36\x2c\x01\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x00\x01\x00\x00"

  # build and write the height value in the header
  height = len(b) / 256
  heightbigendian = struct.pack('i', height)
  outbuf += heightbigendian

  # finish writing the static BMP header
  outbuf += "\x01\x00\x18\x00\x00\x00\x00\x00\x00\x2c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

  # re-order the byte array so the top-left pixel will correspond with the first byte value
  # this allows the image to be constructed left-to-right, top-to-bottom
  output = bytearray()
  for i in range(height, 0, -1):
    startval = ( i - 1 ) * 256
    stopval = startval + 256
    output.extend(b[startval:stopval])

  # write each byte value 3 times to populate the BGR values for each pixel, producing a 256-shade grayscale output
  # optionally, one or two BGR levels can be muted conditionally based on byte values (i.e. ASCII colorization)
  for i in range(len(output)):
    a = chr(output[i])
    outbuf += a + a + a

  return outbuf


def black_to_color(val):
  val = (val / 255.0)
  rgb = colorsys.hsv_to_rgb(val, 0.99, val)

  return (int(rgb[0]*255), int(rgb[1]*255), int(rgb[2]*255))


# http://cmattoon.com/visual-binary-analysis-python/
# slightly modified to fit need
def file_to_pngimage(filename, width=256, maxsize=180000, enable_colors=True):
  size = (width, 1)
  pixels = (size[0] * size[1])

  bytes = ''
  with open(filename, 'rb') as fd:
    while True:
      byteblock = fd.read(1024)
      if byteblock:
        bytes += byteblock
        if len(bytes) < maxsize:
          continue
      break

  bytes = [ord(byte) for byte in bytes]
  bytes = bytes if maxsize is None else bytes[:maxsize]

  if enable_colors:
    img = [black_to_color(b) for b in bytes]
  else:
    img = [(b,b,b) for b in bytes]

  lines = int(len(bytes) / size[0])+1
  size = (size[0], lines)
  im = Image.new('RGB', size)
  im.putdata(img)
  pngimage = StringIO()
  im.save(pngimage, format='PNG')

  return pngimage.getvalue()


def buf_to_pngimage(buf, width=256, maxsize=180000, enable_colors=True):
  size = (width, 1)
  pixels = (size[0] * size[1])

  bytes = buf
  bytes = [ord(byte) for byte in bytes]
  bytes = bytes if maxsize is None else bytes[:maxsize]

  if enable_colors:
    img = [black_to_color(b) for b in bytes]
  else:
    img = [(b,b,b) for b in bytes]

  lines = int(len(bytes) / size[0])+1
  size = (size[0], lines)
  im = Image.new('RGB', size)
  im.putdata(img)
  pngimage = StringIO()
  im.save(pngimage, format='PNG')

  return pngimage.getvalue()


def file_to_pdf(filename):
  pdffile = '%s.pdf' % (os.path.basename(filename))
  pdffile = StringIO()
  pdfkit.from_file(filename, pdffile)

  print pdffile.getvalue()
  return None


def ipapi_json(ipaddr):
  # http://ip-api.com/json/8.8.8.8
  return


# replace all empty or "NA" values in dicts with None
# needs testing
"""
  indict = {
    'a': "",
    'b': '',
    'c': "NA",
    'd': 'NA',
    'e': 1,
    'f': {
      'fa': "",
      'fb': '',
      'fc': "NA",
      'fd': 'NA',
      'fe': 1,
      'ff': ['11', 22, 'ab', "", {1: ""}]
    },
    'g': [1, 'r', 66, '', 99]
  }
"""
def dict_normalize(indict):
  if not isinstance(indict, dict):
    return indict

  for k, v in indict.iteritems():
    if isinstance(v, dict):
      dict_normalize(v)

    elif isinstance(v, list):
      for idx, item in enumerate(v):
        if isinstance(item, dict):
          dict_normalize(item)
        if isinstance(item, list):
          dict_normalize(item)
        elif isinstance(item, str):
          if not item or item == 'NA':
            indict[k][idx] = None

    elif isinstance(v, str):
      if not v or v == 'NA':
        indict[k] = None

  return indict

