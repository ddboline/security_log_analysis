# -*- coding: utf-8 -*-
"""
Created on Wed Sep 30 07:32:45 2015

@author: ddboline
"""

import datetime
from security_log_analysis.db_tables import (create_tables, delete_tables)
from security_log_analysis.util import (OpenPostgreSQLsshTunnel, create_db_engine)
from security_log_analysis.security_log_parse import (
    find_originating_country, analyze_single_line_ssh, analyze_single_file_ssh,
    parse_apache_time_str, analyze_single_file_apache, read_country_code, read_host_country,
    analyze_files)


def test_find_originating_country():
    with OpenPostgreSQLsshTunnel(port=5434) as pport:
        engine = create_db_engine(port=pport)
        country_list = read_country_code(engine)

    host = 'host-219-235-1-84.iphost.gotonets.com'
    country = find_originating_country(hostname=host, country_code_list=country_list)
    assert country == 'CN'


def test_analyze_single_line_ssh():
    line = 'Sep 27 10:42:47 dilepton-tower sshd[31950]: Failed password ' + \
           'for root from 218.87.111.108 port 33104 ssh2'
    assert analyze_single_line_ssh(line) == (None, None, None)
    line = 'Sep 27 10:42:45 dilepton-tower sshd[31950]: ' + \
           'pam_unix(sshd:auth): authentication failure; logname= uid=0 ' + \
           'euid=0 tty=ssh ruser= rhost=218.87.111.108  user=root'
    result = analyze_single_line_ssh(line)
    print(result)
    assert analyze_single_line_ssh(line) == (datetime.datetime(2017, 9, 27, 10, 42, 45),
                                             '218.87.111.108', 'root')


def test_analyze_single_file_ssh():
    result = [(datetime.datetime(2017, 9, 27, 10, 42, 45), '218.87.111.108', 'root'),
              (datetime.datetime(2017, 9, 27, 10, 43, 3), '218.87.111.108', 'root')]
    with open('tests/test_ssh.log') as infile:
        output = [x for x in analyze_single_file_ssh(infile)]
    print(output)
    print(result)
    assert output == result


def test_parse_apache_time_str():
    test = '27/Sep/2015:20:41:44'
    result = datetime.datetime(2015, 9, 27, 20, 41, 44)
    assert parse_apache_time_str(test) == result


def test_analyze_single_file_apache():
    result = [(datetime.datetime(2015, 9, 28, 4, 36), '184.105.247.196'),
              (datetime.datetime(2015, 9, 28, 4, 44, 15), '184.105.247.196'),
              (datetime.datetime(2015, 9, 28, 17, 56, 51), '62.128.213.24'),
              (datetime.datetime(2015, 9, 28, 19, 39, 58), '54.77.239.4'),
              (datetime.datetime(2015, 9, 28, 20, 50, 46), '184.105.139.68'),
              (datetime.datetime(2015, 9, 28, 20, 56, 31), '184.105.139.68'),
              (datetime.datetime(2015, 9, 28, 21, 19, 20), '109.123.101.28'),
              (datetime.datetime(2015, 9, 28, 23, 36, 45), '46.165.220.215')]
    with open('tests/test_apache.log') as infile:
        output = sorted([x for x in analyze_single_file_apache(infile)])
    print(output)
    print(result)
    assert output == result


def test_read_country_code():
    with OpenPostgreSQLsshTunnel(port=5435) as pport:
        engine = create_db_engine(port=pport)
        country_code = read_country_code(engine)

    print(len(country_code))
    assert len(country_code) == 250
    assert country_code['IL'] == 'Israel'


def test_read_host_country():
    with OpenPostgreSQLsshTunnel(port=5436) as pport:
        engine = create_db_engine(port=pport)
        host_country = read_host_country(engine)

    assert len(host_country) >= 13754
    assert host_country['218.87.111.108'] == 'CN'


def test_analyze_files():
    with OpenPostgreSQLsshTunnel(port=5437) as pport:
        engine = create_db_engine(port=pport, dbname='test_ssh_intrusion_logs')
        create_tables(engine)
        output = analyze_files(engine, test=True)
        print(output)
        assert output >= 0
        delete_tables(engine)


def test_db_tables():
    import security_log_analysis.db_tables as db_tables
    for label in dir(db_tables):
        val = getattr(db_tables, label)
        if hasattr(val, '__tablename__'):
            print(val)
