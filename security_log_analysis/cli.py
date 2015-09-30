#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""
Command Line Interface
"""
from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging

import security_log_analysis
from security_log_analysis.security_log_parse import (analyze_files,
                                                      fill_country_plot,
                                                      plot_time_access,
                                                      local_remote_comparison)
from security_log_analysis.util import (OpenPostgreSQLsshTunnel,
                                        create_db_engine)

__author__ = "Daniel Boline"
__copyright__ = "Daniel Boline"
__license__ = "none"

_logger = logging.getLogger(__name__)


def parse_args(args):
    """
    Parse command line parameters

   :param args: command line parameters as list of strings
   :return: command line parameters as:obj:`argparse.Namespace`
    """
    parser = argparse.ArgumentParser(
        description="Just a Hello World demonstration")
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='security_log_analysis ...')
    return parser.parse_args(args)


def main(args):
    args = parse_args(args)
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        print(analyze_files(engine))
    _logger.info("Script ends here")


def run():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    main(sys.argv[1:])

def analyze(data_path):
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        fill_country_plot(engine, data_path)
        for table in ('ssh_log', 'ssh_log_cloud', 'apache_log',
                      'apache_log_cloud'):
            plot_time_access(engine, table, table)
        print('\nssh local remote comparison')
        local_remote_comparison(engine)
        print('\napache local remote comparison')
        local_remote_comparison(engine, table='local_remote_compare_apache')

def run_analyze():
    return analyze(security_log_analysis.__path__[0])

if __name__ == "__main__":
    run()
