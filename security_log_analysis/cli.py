#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""
Command Line Interface
"""
from __future__ import division, print_function, absolute_import

import security_log_analysis
from security_log_analysis.security_log_parse import (analyze_files,
                                                      fill_country_plot,
                                                      plot_time_access,
                                                      local_remote_comparison)
from security_log_analysis.util import (OpenPostgreSQLsshTunnel,
                                        create_db_engine)

def run_parse():
    """
        Open connection with postgresql database
        create engine
        run analyze_files
    """
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        print(analyze_files(engine))

def run_analyze(data_path=security_log_analysis.__path__[0]):
    """
        Open connection with postgresql database
        create engine
        plot time domain frequencies
        print local / remote comparison
    """
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
