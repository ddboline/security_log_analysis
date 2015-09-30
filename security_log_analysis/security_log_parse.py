#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""

"""
from __future__ import division, print_function, absolute_import

import glob
import gzip
import time
import datetime
import logging
from subprocess import Popen, PIPE
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from .db_tables import (CountryCode, HostCountry, SSHLog, SSHLogCloud,
                        ApacheLog, ApacheLogCloud)
from .util import (HOSTNAME, OpenPostgreSQLsshTunnel, create_db_engine)

_logger = logging.getLogger(__name__)

MONTH_NAMES = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
               'Oct', 'Nov', 'Dec')

OWN_HOSTS = ('24.44.92.189', '129.49.56.207', '75.72.228.84',
             'ddbolineathome.mooo.com', 'ool-182c5cbd.dyn.optonline.net',
             'dboline.physics.sunysb.edu')

def find_originating_country(hostname, country_code_list=None, orig_host=None):
    """ Find country associated with hostname, using whois """
    if not hasattr(hostname, 'split'):
        return None
    if '.' not in hostname:
        return None
    if len(hostname.split('.')) < 2:
        return None
    if not orig_host:
        orig_host = hostname

    output = []
    result = 'find hostname country: %s ' % hostname
    ents = hostname.split('.')
    if len(ents) > 2 and country_code_list and ents[-1].upper() in \
            country_code_list:
        return ents[-1].upper()

    pipe = Popen('whois %s' % hostname, shell=True, stdin=PIPE,
                 stdout=PIPE, close_fds=True)
    wfile = pipe.stdout
    output = [l for l in wfile]
    pipe.wait()

    output = ''.join(['%s' % s.decode(errors='ignore') for s in output])

    if 'Your connection limit exceeded. Please slow down and try again later.'\
            in output or 'Timeout' in output:
        time.sleep(10)
        print(hostname)
        return find_originating_country(hostname,
                                        country_code_list=country_code_list,
                                        orig_host=orig_host)

    country = None
    for line in output.split('\n'):
        if 'country' in line or 'Country' in line:
            cn_ = line.split()[-1]
            if cn_ in country_code_list.values():
                _dict = {v: k for (k, v) in country_code_list.items()}
                return _dict[cn_]
            cn_ = line.split()[-1][-2:].upper()
            if country != cn_:
                if country is not None:
                    print('country? %s %s %s' % (country, cn_, hostname))
                country = cn_
        if 'Brazilian resource' in line:
            country = 'BR'

    if 'whois.nic.ad.jp' in output:
        country = 'JP'

    if 'KOREAN' in output:
        country = 'KR'

    if 'hinet.net' in output:
        country = 'CN'

    if not country and hostname:
        country = find_originating_country('.'.join(hostname.split('.')[1:]),
                                           country_code_list=country_code_list,
                                           orig_host=orig_host)

    if country:
        result += country

    return country

def analyze_single_line_ssh(line):
    """ Analyze single line from ssh log file """
    if 'pam_unix' not in line and 'Invalid user' not in line:
        return None, None, None
    ents = line.split()
    month = MONTH_NAMES.index(ents[0]) + 1
    day = int(ents[1])
    hr_ = int(ents[2][0:2])
    mn_ = int(ents[2][3:5])
    sc_ = int(ents[2][6:8])

    date = datetime.datetime(year=2014, month=month, day=day, hour=hr_,
                             minute=mn_, second=sc_)
    if month <= datetime.datetime.now().month:
        date = datetime.datetime(year=2015, month=month, day=day, hour=hr_,
                                 minute=mn_, second=sc_)

    pname = ents[4].split('[')[0]
    if pname != 'sshd':
        date, host, user = None, None, None
    elif ents[5:7] == ['Invalid', 'user']:
        user = None
        host = ents[-1]
        if len(ents) == 10:
            user = ents[-3]
    elif 'pam_unix' not in ents[5]:
        date, host, user = None, None, None
    else:
        host, user = 2*['']
        for ent in ents[6:]:
            if 'rhost' in ent:
                host = ent.replace('rhost=', '')
            elif 'user' in ent:
                user = ent.replace('user=', '')
    return date, host, user

def analyze_single_file_ssh(infile):
    """ Analyze single ssh log file """
    for line in infile:
        dt_, hst, usr = analyze_single_line_ssh(line)
        if hst in OWN_HOSTS:
            continue
        if dt_ and hst and usr:
            yield (dt_, hst, usr)

def parse_apache_time_str(timestr):
    """ Parse apache time string """
    day = int(timestr[:2])
    mon = int(MONTH_NAMES.index(timestr[3:6]))+1
    year = int(timestr[7:11])
    hour = int(timestr[12:14])
    minute = int(timestr[15:17])
    second = int(timestr[18:20])
    return datetime.datetime(year=year, month=mon, day=day, hour=hour,
                             minute=minute, second=second)

def analyze_single_file_apache(infile):
    """ Analyze single line of apache log file """
    for line in infile:
        try:
            hst = line.split()[0]
            dt_ = parse_apache_time_str(line.split()[3].replace('[', ''))
            if hst in OWN_HOSTS:
                continue
            yield (dt_, hst)
        except:
            continue

def analyze_files(engine, test=False):
    """ Analyze log files """
    number_analyzed = 0
    
    country_code = read_country_code(engine)
    host_country = read_host_country(engine)

    table = SSHLog
    if HOSTNAME != 'dilepton-tower':
        table = SSHLogCloud

    session = sessionmaker(bind=engine)
    db = session()
    maxdt = db.query(func.max(table.datetime))[0][0]
    maxid = db.query(func.max(table.id))[0][0]+1
    for fname in glob.glob('/var/log/auth.log*'):
        print(fname)
        open_fn = open
        if '.gz' in fname:
            open_fn = gzip.open
        with open_fn(fname, 'r') as logf:
            for dt_, hst, usr in analyze_single_file_ssh(logf):
                if dt_ <= maxdt:
                    continue
                print(dt_, hst, usr)
                if hst not in host_country:
                    code = find_originating_country(
                                    hst, country_code_list=country_code)
                    if code:
                        host_country[hst] = code
                        db.add(HostCountry(host=hst, code=code))
                        print(hst, code)
                db.add(table(datetime=dt_, host=hst, username=usr, id=maxid))
                number_analyzed += 1
                if test:
                    break
                db.commit()

    table = ApacheLog
    if HOSTNAME != 'dilepton-tower':
        table = ApacheLogCloud
    maxdt = db.query(func.max(table.datetime))[0][0]
    maxid = db.query(func.max(table.id))[0][0]+1
    for fname in glob.glob('/var/log/apache2/access.log*') + \
            glob.glob('/var/log/apache2/ssl_access.log'):
        print(fname)
        open_fn = open
        if '.gz' in fname:
            open_fn = gzip.open
        with open_fn(fname, 'r') as logf:
            for dt_, hst in analyze_single_file_apache(logf):
                if dt_ <= maxdt:
                    continue
                print(dt_, hst)
                if hst not in host_country:
                    code = find_originating_country(
                                    hst, country_code_list=country_code)
                    if code:
                        host_country[hst] = code
                        db.add(HostCountry(host=hst, code=code))
                        print(hst, code)
                db.add(table(datetime=dt_, host=hst, id=maxid))
                if test:
                    break
                db.commit()
    return number_analyzed

def read_country_code(engine):
    country_code = {}
    session = sessionmaker(bind=engine)
    db = session()
    for row in db.query(CountryCode).all():
        country_code[row.code] = row.country
    db.close()
    return country_code

def read_host_country(engine):
    host_country = {}
    session = sessionmaker(bind=engine)
    db = session()
    for row in db.query(HostCountry).all():
        host_country[row.host] = row.code
    return host_country
