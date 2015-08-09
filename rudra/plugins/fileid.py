import pygal
from pygal import Config
from pygal.style import LightColorizedStyle, RedBlueStyle, CleanStyle

import os
import logging.config
import rudra.libs.utils as utils


class FileID:
  def __init__(self, config={}):
    self.logger = logging.getLogger(__name__)

    self.config = config
    self.report =  {
      'filename': None,
      'filetype': None,
      'filecategory': None,
      'filemimetype': None,
      'filemagic': None,
      'filesize': None,
      'fileminsize': None,
      'filecompressionratio': None,
      'fileentropy': None,
      'fileentropy_category': None,
      'hashes': {
        'crc32': None,
        'md5': None,
        'sha1': None,
        'sha256': None,
        'sha512': None,
        'ssdeep': None
      },
      'tags': [],
      'firstseen': None,
      'lastseen': None
    }

    self.pcapmimetypes = config['pcap_mimetypes']


  def identify(self, filename):
    self.report['filename'] = os.path.basename(filename)
    self.report['filename_absolute'] = filename
    self.report['filemimetype'] = utils.file_mimetype(filename)
    self.report['filemagic'] = utils.file_magic(filename)
    if self.report['filemimetype'] in self.pcapmimetypes:
      self.report['filecategory'] = 'CAP'
      self.report['filetype'] = 'PCAP'
      self.logger.info('Identified %s as type %s (%s)' % (self.report['filename'], self.report['filetype'], self.report['filemimetype']))
    else:
      self.logger.info('File %s of type %s is not supported in the current version' % (self.report['filename'], self.report['filemimetype']))
      return None

    self.logger.debug('Calculating file hashes for %s' % (self.report['filename']))
    self.report['hashes']['crc32'] = utils.file_hashes(filename, 'crc32')
    self.report['hashes']['md5'] = utils.file_hashes(filename, 'md5')
    self.report['hashes']['sha1'] = utils.file_hashes(filename, 'sha1')
    self.report['hashes']['sha256'] = utils.file_hashes(filename, 'sha256')
    self.report['hashes']['sha512'] = utils.file_hashes(filename, 'sha512')
    self.report['hashes']['ssdeep'] = utils.file_hashes(filename, 'ssdeep')
    self.logger.info('Completed crc32/md5/sha{1,256,512}/ssdeep hash calculations')

    if self.config['enable_entropy_compression_stats']:
      self.logger.debug('Collecting entropy compression stats for %s' % (self.report['filename']))
      stats = utils.entropy_compression_stats(filename)
      self.report['filesize'] = stats['filesizeinbytes']
      self.report['fileminsize'] = float(stats['minfilesize'])
      self.report['filecompressionratio'] = float(stats['compressionratio'])
      self.report['fileentropy'] = float(stats['shannonentropy'])

      # if entropy falls within the 0 - 1 or 7 - 8 range, categorize as suspicious
      if (self.report['fileentropy'] > 0 and self.report['fileentropy'] < 1) or self.report['fileentropy'] > 7:
        self.report['fileentropy_category'] = 'SUSPICIOUS'
      else:
        self.report['fileentropy_category'] = 'NORMAL'

      self.logger.info('Completed entropy compression stats collection')

    else:
      stats = {}

    if self.config['enable_bytefreq_histogram']:
      self.logger.debug('Generating Byte-Frequency histogram for %s' % (self.report['filename']))
      config = Config()
      config.x_title = 'Bytes'
      config.y_title = 'Frequency'

      config.x_scale = .25
      config.y_scale = .25
      config.width = 900
      config.height = 300
      config.title_font_size = 9
      config.tooltip_font_size = 0
      config.tooltip_border_radius = 0
      config.no_data_text = ""

      config.show_legend = False
      config.show_only_major_dots = True
      config.human_readable = False
      config.show_y_labels = False
      config.fill = True

      config.style = CleanStyle
      bar_chart = pygal.Bar(config)

      if 'bytefreqlist' in stats.keys():
        bar_chart.add('', stats['bytefreqlist'])

      self.report['filebytefreqhistogram'] = bar_chart.render(is_unicode=False)
      self.logger.info('Completed Byte-Frequency histogram generation')

    # testing and db support to identify visually similar files/sessions
    if self.config['enable_file_visualization']:
      self.logger.debug('Generating file visualization for %s' % (self.report['filename']))
      self.report['filevis_png'] = utils.file_to_pngimage(filename)
      self.report['filevis_png_bw'] = utils.file_to_pngimage(filename, enable_colors=False)
      self.logger.info('Completed file visualization generation')

    return dict(self.report)

