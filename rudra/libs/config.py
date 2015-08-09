import os
import sys
import ConfigParser
import logging.config

import rudra.libs.utils as utils


class Config:
  def __init__(self, config_file=None):
    logging.config.fileConfig('logging.conf')
    self.logger = logging.getLogger(__name__)

    # max bytes (within respective buffers) to inspect
    self.MAX_INSPECT_UDP_DEPTH = 8192
    self.MAX_INSPECT_CTS_DEPTH = 8192
    self.MAX_INSPECT_STC_DEPTH = 8192

    self.conf = {}

    self.config_file = os.path.abspath(config_file)
    self.config = ConfigParser.SafeConfigParser()
 
    if config_file and utils.is_file(config_file):
      self.config.read(self.config_file)


  def read_as_dict(self):
    for section in self.config.sections():
      for option in self.config.options(section):

        # lists in the config options
        if option in ['input_files', 'reports_type', 'pcap_mimetypes']:
          self.conf[option] = self.config.get(section, option).lower().split(',')

        # booleans in config options
        elif option in [
                          'enable_whois_lookup', 'enable_bytefreq_histogram', 'enable_file_visualization',
                          'enable_bytefreq_histogram_transactions', 'enable_file_visualization_transactions',
                          'enable_google_maps', 'enable_buf_hexdump', 'enable_pcap', 'enable_yara',
                          'enable_shellcode', 'shellcode_show_hexdump', 'enable_regex', 'enable_heuristics', 'enable_interactive',
                          'enable_geoloc', 'enable_yara_strings', 'enable_entropy_compression_stats',
                          'enable_stats_filesize_limit', 'enable_reverse_dns', 'enable_proto_decode'
                        ]:
          if self.config.get(section, option).lower() == 'false':
            self.conf[option] = False

          if self.config.get(section, option).lower() == 'true':
            self.conf[option] = True

        # ints in config options
        elif option in [
                          'yara_match_timeout', 'html_hexdump_bytes', 'stats_filesize_limit',
                          'inspect_udp_depth', 'inspect_cts_depth', 'inspect_stc_depth', 'truncate_length'
                        ]:
          self.conf[option] = int(self.config.get(section, option))

        # anything else ?
        else:
          self.conf[option] = self.config.get(section, option)

    if 'inspect_udp_depth' in self.conf.keys() and (self.conf['inspect_udp_depth'] > self.MAX_INSPECT_UDP_DEPTH or self.conf['inspect_udp_depth'] <= 0):
      self.logger.debug('Imposing max UDP inspection depth: %d (config.inspect_udp_depth: %d)' % (self.MAX_INSPECT_UDP_DEPTH, self.conf['inspect_udp_depth']))
      self.conf['inspect_udp_depth'] = self.MAX_INSPECT_UDP_DEPTH

    if 'inspect_cts_depth' in self.conf.keys() and (self.conf['inspect_cts_depth'] > self.MAX_INSPECT_CTS_DEPTH or self.conf['inspect_cts_depth'] <= 0):
      self.logger.debug('Imposing max CTS inspection depth: %d (config.inspect_cts_depth: %d)' % (self.MAX_INSPECT_CTS_DEPTH, self.conf['inspect_cts_depth']))
      self.conf['inspect_cts_depth'] = self.MAX_INSPECT_CTS_DEPTH

    if 'inspect_stc_depth' in self.conf.keys() and (self.conf['inspect_stc_depth'] > self.MAX_INSPECT_STC_DEPTH or self.conf['inspect_stc_depth'] <= 0):
      self.logger.debug('Imposing max STC inspection depth: %d (config.inspect_stc_depth: %d)' % (self.MAX_INSPECT_STC_DEPTH, self.conf['inspect_stc_depth']))
      self.conf['inspect_stc_depth'] = self.MAX_INSPECT_STC_DEPTH

    return self.conf


  def set_defaults(self):
    self.config.add_section('MISC')
    self.set_var('MISC', 'cwd', './')
    self.set_var('MISC', 'enable_interactive', 'false')
    self.set_var('MISC', 'html_hexdump_bytes', '128')

    self.config.add_section('LOGGING')
    self.set_var('LOGGING', 'logging_dir', './')
    self.set_var('LOGGING', 'logging_file', 'rudra.log')
    self.set_var('LOGGING', 'logging_level', 'DEBUG')

    self.config.add_section('INPUT')
    self.set_var('INPUT', 'input_files', './tests/files/pcaps/shellcode-reverse-tcp-4444.pcap,')
    self.set_var('INPUT', 'bpf', 'ip')
    self.set_var('INPUT', 'html_template', 'report.tmpl')

    self.config.add_section('OUTPUT')
    self.set_var('OUTPUT', 'reports_dir', './reports')
    self.set_var('OUTPUT', 'reports_type', 'json, html, pdf')
    self.set_var('OUTPUT', 'enable_bytefreq_histogram', 'true')
    self.set_var('OUTPUT', 'enable_google_maps', 'true')
    self.set_var('OUTPUT', 'enable_whois_lookup', 'true')

    self.config.add_section('ANALYSIS')
    self.set_var('ANALYSIS', 'enable_pcap', 'true')
    self.set_var('ANALYSIS', 'pcap_engine', 'libnids')
    self.set_var('ANALYSIS', 'enable_yara', 'true')
    self.set_var('ANALYSIS', 'yara_rules_dir', './data/yararules')
    self.set_var('ANALYSIS', 'yara_match_timeout', '60')
    self.set_var('ANALYSIS', 'enable_shellcode', 'true')


  def get_var(self, section, var):
    try:
      return self.config.get(section, var)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
      return None


  def get_section(self, section):
    try:
      options = self.config.items(section)
    except ConfigParser.NoSectionError:
      return None

    opt_dict = dict()
    for pairs in options:
      opt_dict[pairs[0]] = pairs[1]

    return opt_dict


  def set_var(self, section, var, value):
    try:
      return self.config.set(section, var, value)
    except ConfigParser.NoSectionError:
      return None


  def list_config(self):
    print "Configuration Options:"
    for section in self.config.sections():
      print "%s" % (section)
      for (name, value) in self.config.items(section):
        print "\t%s:\t%s" % (name, value)
    return
