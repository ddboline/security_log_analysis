#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""
    Dummy conftest.py for security_log_analysis.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""
from __future__ import print_function, absolute_import, division

import pytest

import datetime
import pandas as pd
from security_log_analysis.util import (OpenPostgreSQLsshTunnel,
                                        create_db_engine)
from security_log_analysis.security_log_parse import (
                                                find_originating_country,
                                                analyze_single_line_ssh,
                                                analyze_single_file_ssh,
                                                parse_apache_time_str,
                                                analyze_single_file_apache,
                                                read_country_code,
                                                read_host_country,
                                                analyze_files)

def test_find_originating_country():
    ccode_df = pd.read_csv('country_code_name.csv.gz', compression='gzip')
    country_list = dict(zip(ccode_df['Code'], ccode_df['Country']))

    host = 'host-219-235-1-84.iphost.gotonets.com'
    country = find_originating_country(hostname=host,
                                       country_code_list=country_list)
    assert country == 'CN'

def test_analyze_single_line_ssh():
    line = 'Sep 27 10:42:47 dilepton-tower sshd[31950]: Failed password ' + \
           'for root from 218.87.111.108 port 33104 ssh2'
    assert analyze_single_line_ssh(line) == (None, None, None)
    line = 'Sep 27 10:42:45 dilepton-tower sshd[31950]: ' + \
           'pam_unix(sshd:auth): authentication failure; logname= uid=0 ' + \
           'euid=0 tty=ssh ruser= rhost=218.87.111.108  user=root'
    assert analyze_single_line_ssh(line) == (datetime.datetime(2015, 9, 27, 10,
                                                               42, 45),
                                             '218.87.111.108', 'root')

def test_analyze_single_file_ssh():
    result = [
        (datetime.datetime(2015, 9, 27, 10, 42, 45), '218.87.111.108', 'root'),
        (datetime.datetime(2015, 9, 27, 10, 43, 3), '218.87.111.108', 'root')]
    with open('tests/test_ssh.log') as infile:
        output = [x for x in analyze_single_file_ssh(infile)]
    assert output == result

def test_parse_apache_time_str():
    test = '27/Sep/2015:20:41:44'
    result = datetime.datetime(2015, 9, 27, 20, 41, 44)
    assert parse_apache_time_str(test) == result

def test_analyze_single_file_apache():
    result = [(datetime.datetime(2015, 9, 27, 20, 41, 44), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 41, 45), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 41, 45), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 41, 45), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 41, 46), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 43, 6), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 43, 7), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 43, 7), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 43, 7), '67.84.145.194'),
              (datetime.datetime(2015, 9, 27, 20, 43, 39), '67.84.145.194')]
    with open('tests/test_apache.log') as infile:
        output = [x for x in analyze_single_file_apache(infile)]
    assert output == result

def test_read_country_code():
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        country_code = read_country_code(engine)

    assert len(country_code) == 249
    assert country_code['IL'] == 'Israel'

def test_read_host_country():
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        host_country = read_host_country(engine)

    assert len(host_country) >= 13754
    assert host_country['218.87.111.108'] == 'CN'

def test_analyze_files():
    with OpenPostgreSQLsshTunnel():
        engine = create_db_engine()
        analyze_files(engine, test=True)

    assert False
