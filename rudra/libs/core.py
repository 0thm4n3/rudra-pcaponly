import os
import sys
import code
import copy
import time
import pprint
import logging.config

from rudra import get_version_string, get_author
from rudra.plugins.pcapanalysis import PCAPAnalysis
from rudra.plugins.protodecode import ProtoDecode
from rudra.plugins.fileid import FileID
from rudra.libs.inspect import Inspect
from rudra.libs.report import Report
import rudra.libs.utils as utils


class Rudra:
  def __init__(self, session={}):
    starttime = time.time()

    logging.config.fileConfig('logging.conf')
    self.logger = logging.getLogger(__name__)

    self.session = session

    self.session['banner'] = utils.to_base64("""
                    .___
  _______  __ __   __| _/_______ _____
  \_  __ \|  |  \ / __ | \_  __ \\\\__  \\
   |  | \/|  |  // /_/ |  |  | \/ / __ \_
   |__|   |____/ \____ |  |__|   (____  / v%s
                      \/              \/ (%s)
    """ % (get_version_string(), get_author()))
    print utils.from_base64(self.session['banner'])

    self.session['report'] = {}

    if self.session['config']['enable_interactive']:
      print ' Use the "self" object to analyze files'
      self.interactive()

    elif self.session['config']['input_files'] and len(self.session['config']['input_files']) > 0:
      for f in self.session['config']['input_files']:
        self.analyze(f)

    else:
      self.logger.error('Please use -f to specify a file or use -i for interactive mode')

    endtime = time.time()
    self.session['report']['starttime'] = starttime
    self.session['report']['endtime'] = endtime
    del starttime, endtime

    self.session['report']['elapsedtime'] = self.session['report']['endtime'] - self.session['report']['starttime']
    print 'Total scan time: %s' % (utils.hms_string(self.session['report']['elapsedtime']))


  def __str__(self):
    return pprint.PrettyPrinter().pformat(self.report)


  def __repr__(self):
    return self.__str__()


  def analyze(self, filename):
    if not utils.is_file(filename):
      self.logger.error('%s is not a file.' % filename)
      return

    ## refrain scanning a file more than once
    ## include db checks and ensure config similarity
    ## or check if the report file already exists in reports directory

    else:
      self.logger.info('Starting analysis on file %s' % filename)

    self.session['report']['firstseen'] = utils.time_now_json(self.session['config']['timezone'])
    self.session['report']['lastseen'] = utils.time_now_json(self.session['config']['timezone'])

    filesize = utils.file_size(filename)
    if self.session['config']['stats_filesize_limit'] == 0 or filesize <= self.session['config']['stats_filesize_limit']:
      # limit is equal to 0
      # or
      # filesize is lesser than limit
      # all good, keep going
      pass
    else:
      self.logger.warn('Disabling entropy compression stats calculation and file visualization (filesize: %d, stats_filesize_limit: %d)' % (filesize, self.session['config']['stats_filesize_limit']))
      self.session['config']['enable_entropy_compression_stats'] = False
      self.session['config']['enable_bytefreq_histogram'] = False
      self.session['config']['enable_file_visualization'] = False

    if not self.session['config']['enable_entropy_compression_stats']:
      # if stats are not computed
      # histogram can't be shown, so disable it explicitly
      self.session['config']['enable_bytefreq_histogram'] = False

    if not self.session['config']['enable_geoloc']:
      # if geodata lookup is disabled
      # map cannot shown, so disable it explicitly
      self.session['config']['enable_google_maps'] = False

    # identify filetype and populate reports
    self.logger.info('Invoking fileid module for type identification and metadata collection')
    fileid = FileID(self.session['config'])
    fileidreport = fileid.identify(filename)

    # initialize fileid specific classes and call analysis methods
    if fileidreport and fileidreport['filecategory'] == 'CAP' and fileidreport['filetype'] == 'PCAP':
      if self.session['config']['enable_pcap']:
        self.logger.info('Invoking pcapanalysis module for host identification, dns/http/ftp/smtp/pop3/imap probing and flow inspection')
        pcapid = PCAPAnalysis(self.session['config'])
        pcapreport = pcapid.analyze(filename)

      else:
        pcapreport = None

      if pcapreport:
        # for all http sessions,
        # identify and split transactions
        pcapreport = ProtoDecode(self.session['config']).http_transactions(pcapreport)

        if self.session['config']['enable_proto_decode']:
          self.logger.info('Invoking HTTP/SMTP/IMAP/POP3 protocol decode module')
          pcapreport = ProtoDecode(self.session['config']).decode(pcapreport, fileidreport['filetype'])

        self.logger.info('Invoking inspection module')
        pcapreport = Inspect(self.session['config']).inspect(pcapreport, fileidreport['filetype'])

        # populate rudra reports dict with appropriate sections
        self.session['report']['filestats'] = fileidreport
        self.session['report']['pcap'] = pcapreport

        ## populate results into db

        # include some meta info in the report
        ## add scantime
        self.session['metainfo'] = {
          'datetime': utils.get_current_datetime(),
          'rudraversion': "rudra v%s" % (get_version_string())
        }

        # encode all unsafe dict values to base64 and append _b64 to respective keynames
        self.logger.info('Invoking report dict sanitization module: adds _b64 keys')
        self.session['report'] = self.report_sanitize(self.session['report'])

        # normalize dict to have a consistent representation of empty/uninitialized values
        self.logger.info('Invoking report dict normalization module: cleans empty key:value pairs')
        self.session['report'] = utils.dict_normalize(self.session['report'])

        # write reports in supported formats to reports directory
        self.logger.info('Invoking reporting module to generate reports in requested formats')
        Report().generate_report(self.session)
        self.logger.info('Completed report generation: reports/%s.*' % self.session['report']['filestats']['hashes']['sha256'])

      else: # pcapanalysis returned none
        return

    else: # not a pcap file
      return


  # Inspired from following posts:
  # https://github.com/k4ml/importerror/blob/master/posts/python-custom-interactive-console.md
  # stackoverflow.com/questions/19754458/open-interactive-python-console-from-a-script
  def interactive(self):
    utils.set_prompt(ps1='(rudra) ', ps2='... ')

    import os
    import readline
    import rlcompleter
    import atexit

    vars = globals()
    vars.update(locals())
    histfile = os.path.join(os.environ["HOME"], ".rudrahistory")
    readline.set_completer(rlcompleter.Completer(vars).complete)
    readline.parse_and_bind("tab: complete")

    if os.path.isfile(histfile):
      readline.read_history_file(histfile)
    atexit.register(readline.write_history_file, histfile)

    for pythonrc in (os.environ.get("PYTHONSTARTUP"), os.path.expanduser('~/.pythonrc.py')):
      if pythonrc and os.path.isfile(pythonrc):
        try:
          with open(pythonrc) as handle:
            exec(compile(handle.read(), pythonrc, 'exec'))
        except NameError:
          pass

    del os, histfile, readline, rlcompleter, atexit
    code.interact(banner='', local=vars)


  def report_sanitize(self, report):
    sanreport = copy.deepcopy(report)

    if 'filebytefreqhistogram' in report['filestats']:
      sanreport['filestats']['filebytefreqhistogram_b64'] = utils.to_base64(report['filestats']['filebytefreqhistogram'])
      del sanreport['filestats']['filebytefreqhistogram']

    if 'filevis_png' in report['filestats']:
      sanreport['filestats']['filevis_png_b64'] = utils.to_base64(report['filestats']['filevis_png'])
      del sanreport['filestats']['filevis_png']

    if 'filevis_png_bw' in report['filestats']:
      sanreport['filestats']['filevis_png_bw_b64'] = utils.to_base64(report['filestats']['filevis_png_bw'])
      del sanreport['filestats']['filevis_png_bw']

    for k in sorted(report['pcap']['flows'].keys()):
      proto = k.split(' - ')[2]

      for host in report['pcap']['hosts']:
        if 'whois_text' in report['pcap']['hosts'][host].keys() and 'whois_text_b64' not in sanreport['pcap']['hosts'][host].keys():
          sanreport['pcap']['hosts'][host]['whois_text_b64'] = utils.to_base64(report['pcap']['hosts'][host]['whois_text'])
          del sanreport['pcap']['hosts'][host]['whois_text']
        else:
          sanreport['pcap']['hosts'][host]['whois_text_b64'] = None

      if 'ctsbuf' in sanreport['pcap']['flows'][k].keys() and sanreport['pcap']['flows'][k]['ctsbuf']:
        del sanreport['pcap']['flows'][k]['ctsbuf']

      if 'stcbuf' in sanreport['pcap']['flows'][k].keys() and sanreport['pcap']['flows'][k]['stcbuf']:
        del sanreport['pcap']['flows'][k]['stcbuf']

      if 'transactions' in report['pcap']['flows'][k].keys() and report['pcap']['flows'][k]['transactions']:
        for tid in sorted(report['pcap']['flows'][k]['transactions']):
          if ('bufvis_png' and 'bufvis_bw_png') in report['pcap']['flows'][k]['transactions'][tid].keys():
            sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_png_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['bufvis_png'])
            sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_bw_png_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['bufvis_bw_png'])
            del sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_png']
            del sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_bw_png']
          else:
            sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_png_b64'] = None
            sanreport['pcap']['flows'][k]['transactions'][tid]['bufvis_bw_png_b64'] = None

          if proto == 'UDP':
            if 'buf' in report['pcap']['flows'][k]['transactions'][tid].keys() and report['pcap']['flows'][k]['transactions'][tid]['buf']:
                sanreport['pcap']['flows'][k]['transactions'][tid]['buf_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['buf'])
                del sanreport['pcap']['flows'][k]['transactions'][tid]['buf']
            else:
              sanreport['pcap']['flows'][k]['transactions'][tid]['buf_b64'] = None
              del sanreport['pcap']['flows'][k]['transactions'][tid]['buf']

          if proto == 'TCP':
            if 'ctsbuf' in report['pcap']['flows'][k]['transactions'][tid] and report['pcap']['flows'][k]['transactions'][tid]['ctsbuf']:
              sanreport['pcap']['flows'][k]['transactions'][tid]['ctsbuf_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['ctsbuf'])
              del sanreport['pcap']['flows'][k]['transactions'][tid]['ctsbuf']
            else:
              sanreport['pcap']['flows'][k]['transactions'][tid]['ctsbuf_b64'] = None
              del sanreport['pcap']['flows'][k]['transactions'][tid]['ctsbuf']

            for key in report['pcap']['flows'][k]['transactions'][tid]['ctsdecode'].keys():
              sanreport['pcap']['flows'][k]['transactions'][tid]['ctsdecode']['%s_b64' % (key)] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['ctsdecode'][key])
              del sanreport['pcap']['flows'][k]['transactions'][tid]['ctsdecode'][key]

            if report['pcap']['flows'][k]['transactions'][tid]['regex']['cts']:
              for matchid in report['pcap']['flows'][k]['transactions'][tid]['regex']['cts'].keys():
                sanreport['pcap']['flows'][k]['transactions'][tid]['regex']['cts'][matchid]['match_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['regex']['cts'][matchid]['match'])
                del sanreport['pcap']['flows'][k]['transactions'][tid]['regex']['cts'][matchid]['match']

            if report['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']:
              for matchid in report['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts'].keys():
                sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['buf_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['buf'])
                sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['profile_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['profile'])
                if 'buf' in sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts'].keys():
                  del sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['buf']

                if 'profile' in sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts'].keys():
                  del sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['cts']['profile']

            if 'stcbuf' in report['pcap']['flows'][k]['transactions'][tid] and report['pcap']['flows'][k]['transactions'][tid]['stcbuf']:
              sanreport['pcap']['flows'][k]['transactions'][tid]['stcbuf_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['stcbuf'])
              del sanreport['pcap']['flows'][k]['transactions'][tid]['stcbuf']
            else:
              sanreport['pcap']['flows'][k]['transactions'][tid]['stcbuf_b64'] = None
              del sanreport['pcap']['flows'][k]['transactions'][tid]['stcbuf']

            for key in report['pcap']['flows'][k]['transactions'][tid]['stcdecode'].keys():
              sanreport['pcap']['flows'][k]['transactions'][tid]['stcdecode']['%s_b64' % (key)] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['stcdecode'][key])
              del sanreport['pcap']['flows'][k]['transactions'][tid]['stcdecode'][key]

            if report['pcap']['flows'][k]['transactions'][tid]['regex']['stc']:
              for matchid in report['pcap']['flows'][k]['transactions'][tid]['regex']['stc'].keys():
                sanreport['pcap']['flows'][k]['transactions'][tid]['regex']['stc'][matchid]['match_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['regex']['stc'][matchid]['match'])
                del sanreport['pcap']['flows'][k]['transactions'][tid]['regex']['stc'][matchid]['match']

            if report['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']:
              for matchid in report['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc'].keys():
                sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['buf_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['buf'])
                sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['profile_b64'] = utils.to_base64(report['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['profile'])
                if 'buf' in sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc'].keys():
                  del sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['buf']

                if 'profile' in sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc'].keys():
                  del sanreport['pcap']['flows'][k]['transactions'][tid]['shellcode']['stc']['profile']

    #pprint.pprint(sanreport)
    return dict(sanreport)
