#!/usr/bin/env python

import sys
import argparse

from rudra.libs import config
import rudra.libs.core as Rudra
import rudra.libs.utils as utils


def main():
  session = {
    'config': {
      'enable_interactive': False,
      'input_files': [],
      'logging_file': None,
      'reports_dir': None
    }
  }

  parser = argparse.ArgumentParser(description="Rudra - The destroyer of evil")
  parser.add_argument('-c', '--configfile', dest='configfile', action='store', default=None, help='custom config file (default: ./rudra.conf)')
  parser.add_argument('-f', '--inputfile', dest='inputfile', action='append', default=[], help='file to analyze')
  parser.add_argument('-r', '--reportsdir', dest='reportsdir', action='store', default=None, help='custom reports directory (default: ./reports)')
  #parser.add_argument('-i', '--interactive', dest='interactive', action='store_true', default=False, help='invoke interactive mode')
  #parser.add_argument('-d', '--inputdir', dest='inputdir', action='append', default=[], help='directory to analyze')
  #parser.add_argument('-l', '--loggingfile', dest='loggingfile', action='store', default=None, help='custom logging file (default: ./rudra.log)')
  args = parser.parse_args()

  # set user preferred file as config file
  # or use default config file
  if args.configfile:
    configfile = args.configfile
  else:
    configfile = './rudra.conf'

  # read config options from config file set above
  config_obj = config.Config(configfile)
  session['config'] = config_obj.read_as_dict()

  # override config options with user preferences
  # enable interactive mode
  #session['config']['enable_interactive'] = args.interactive

  #if len(args.inputdir) > 0:
  #  for directory in args.inputdir:
  #    if utils.is_dir(directory):
  #      session['config']['input_files'].append(utils.list_all_files(directory))

  #if args.loggingfile:
  #  session['config']['logging_file'] = args.loggingfile

  if len(args.inputfile) > 0:
    session['config']['input_files'] = args.inputfile

  if args.reportsdir:
    session['config']['reports_dir'] = args.reportsdir

  rudra = Rudra.Rudra(session)


if __name__ == '__main__':
  main()
