#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""
    Various functions to parse security logs,
    use whois to find country of origin for each IP address,
    then dump results to postgresql database
"""
from __future__ import division, print_function, absolute_import

import os
import glob
import gzip
import time
import datetime
from socket import gethostbyname
#import logging
from subprocess import Popen, PIPE
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from .db_tables import (CountryCode, HostCountry, SSHLog, SSHLogCloud,
                        ApacheLog, ApacheLogCloud)
from .util import HOSTNAME

#_logger = logging.getLogger(__name__)

MONTH_NAMES = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
               'Oct', 'Nov', 'Dec')

OWN_HOSTS = ('67.84.145.194', '24.44.92.189', '129.49.56.207', '75.72.228.84',
             'ddbolineathome.mooo.com', 'ool-182c5cbd.dyn.optonline.net',
             'dboline.physics.sunysb.edu', '127.0.0.1', '208.105.40.20',
             '192.168.1.1', '108.14.33.127', '52.7.20.216', '68.47.108.255')


def find_originating_country(hostname, country_code_list=None, orig_host=None):
    """ Find country associated with hostname, using whois """
    if not hasattr(hostname, 'split') or '.' not in hostname or \
            len(hostname.split('.')) < 2:
        return None
    if not orig_host:
        orig_host = hostname

    def _worker(hostname):
        output = []
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

        if 'Your connection limit exceeded. Please slow down and try again ' \
                'later.' in output or 'Timeout' in output:
            time.sleep(10)
            print(hostname)
            return find_originating_country(
                hostname, country_code_list=country_code_list,
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
        if not country:
            if 'whois.nic.ad.jp' in hostname:
                country = 'JP'
            elif 'KOREAN' in output:
                country = 'KR'
            elif 'hinet.net' in hostname:
                country = 'CN'
            elif 'contabo.host' in hostname:
                country = 'DE'
            elif hostname.endswith('.eu'):
                country = 'FR'
        return country

    country = _worker(hostname)

    if not country:
        country = _worker(gethostbyname(hostname))

    if not country and hostname:
        return find_originating_country('.'.join(hostname.split('.')[1:]),
                                        country_code_list=country_code_list,
                                        orig_host=orig_host)
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

    curmonth = datetime.datetime.now().month
    curyear = datetime.datetime.now().year
    if month <= curmonth:
        date = datetime.datetime(year=curyear, month=month, day=day, hour=hr_,
                                 minute=mn_, second=sc_)
    else:
        date = datetime.datetime(year=curyear - 1, month=month, day=day,
                                 hour=hr_, minute=mn_, second=sc_)

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
        host, user = 2 * ['']
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
    mon = int(MONTH_NAMES.index(timestr[3:6])) + 1
    year = int(timestr[7:11])
    hour = int(timestr[12:14])
    minute = int(timestr[15:17])
    second = int(timestr[18:20])
    return datetime.datetime(year=year, month=mon, day=day, hour=hour,
                             minute=minute, second=second)


def analyze_single_file_apache(infile):
    """ Analyze single line of apache log file """
    for line in infile:
        hst = line.split()[0]
        dt_ = parse_apache_time_str(line.split()[3].replace('[', ''))
        if hst in OWN_HOSTS:
            continue
        yield (dt_, hst)


def analyze_files(engine, test=False):
    """ Analyze log files """
    number_analyzed = 0

    country_code = read_country_code(engine)
    host_country = read_host_country(engine)

    table = SSHLog
    if HOSTNAME != 'dilepton-tower':
        table = SSHLogCloud

    session = sessionmaker(bind=engine)
    db_ = session()
    maxdt = db_.query(func.max(table.datetime))[0][0]
    maxid = db_.query(func.max(table.id))[0][0]
    if maxid:
        maxid += 1
    else:
        maxid = 0
    for fname in glob.glob('/var/log/auth.log*'):
        print(fname)
        open_fn = open
        if '.gz' in fname:
            open_fn = gzip.open
        with open_fn(fname, 'r') as logf:
            for dt_, hst, usr in analyze_single_file_ssh(logf):
                if maxdt and dt_ <= maxdt:
                    continue
                if hst not in host_country:
                    code = find_originating_country(
                        hst, country_code_list=country_code)
                    if code:
                        host_country[hst] = code
                        db_.add(HostCountry(host=hst, code=code))
                        print(hst, code)
                        db_.commit()
                db_.add(table(datetime=dt_, host=hst, username=usr[:15],
                              id=maxid))
                maxid += 1
                number_analyzed += 1
                db_.commit()
                if test:
                    break

    table = ApacheLog
    if HOSTNAME != 'dilepton-tower':
        table = ApacheLogCloud
    maxdt = db_.query(func.max(table.datetime))[0][0]
    maxid = db_.query(func.max(table.id))[0][0]
    if maxid:
        maxid += 1
    else:
        maxid = 0
    for fname in glob.glob('/var/log/apache2/access.log*') + \
            glob.glob('/var/log/apache2/ssl_access.log'):
        print(fname)
        open_fn = open
        if '.gz' in fname:
            open_fn = gzip.open
        with open_fn(fname, 'r') as logf:
            for dt_, hst in analyze_single_file_apache(logf):
                if maxdt and dt_ <= maxdt:
                    continue
                if hst not in host_country:
                    code = find_originating_country(
                        hst, country_code_list=country_code)
                    if code:
                        host_country[hst] = code
                        db_.add(HostCountry(host=hst, code=code))
                        print(hst, code)
                        db_.commit()
                    else:
                        host_country[hst] = 'EU'
                        db_.add(HostCountry(host=hst, code='EU'))
                        print(hst, 'EU')
                        db_.commit()
                db_.add(table(datetime=dt_, host=hst, id=maxid))
                maxid += 1
                number_analyzed += 1
                db_.commit()
                if test:
                    break
    db_.close()
    return number_analyzed


def read_country_code(engine):
    """
        dump country_code table to dictionary
        country code is 2-digit code taken from ISO-3166-1 alpha-2, see:
        https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
    """
    country_code = {}
    session = sessionmaker(bind=engine)
    db_ = session()
    for row in db_.query(CountryCode).all():
        country_code[row.code] = row.country
    db_.close()
    return country_code


def read_host_country(engine):
    """
        dump host_country table to dictionary
        maps host name to country code
    """
    host_country = {}
    session = sessionmaker(bind=engine)
    db_ = session()
    for row in db_.query(HostCountry).all():
        host_country[row.host] = row.code
    db_.close()
    return host_country


def fill_country_plot(engine, script_path):
    """
        use prexisting database view
        which contains number of entries vs. country
        data is put into a template using an api from google
        to display the data on a map of the world
    """
    table = 'country_count_recent'
    outfname = 'ssh_intrusion_attempts.html'
    if HOSTNAME != 'dilepton-tower':
        table = 'country_count_cloud_recent'
        outfname = 'ssh_intrusion_attempts_cloud.html'

    con = engine.connect()

    with open(outfname, 'w') as output:
        with open('%s/templates/COUNTRY_TEMPLATE.html' % script_path,
                  'r') as inpfile:
            for line in inpfile:
                if 'PUTLISTOFCOUNTRIESANDATTEMPTSHERE' in line:
                    cmd = 'select country, count from %s;' % table
                    for cty, cnt in con.execute(cmd):
                        output.write("%10s['%s', %d],\n" % ('', cty, cnt))
                else:
                    output.write(line)
    con.close()
    if os.path.exists('%s/public_html' % os.getenv('HOME')):
        os.system('mv %s %s/public_html/' % (outfname, os.getenv('HOME')))
    return


def plot_time_access(engine, table, title):
    """
        make plots
    """
    import pandas as pd
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    dtimes = []
    cmd = 'select datetime from %s' % table
    for line in engine.execute(cmd):
        dtimes.append(line[0])

    df_ = pd.DataFrame({'Datetime': dtimes})

    df_['Week'] = df_['Datetime'].apply(lambda d: d.isocalendar()[1])
    df_['Date'] = df_['Datetime'].apply(lambda d: d.date())
    df_['Hours'] = df_['Datetime'].apply(lambda x: (x.hour + x.minute / 60.
                                                    + x.second / 3600.))
    df_['Weekdays'] = df_['Datetime'].apply(lambda x: x.weekday())

    print(table, title)
    print(df_.head())

    sec = df_['Week'].values
    plt.hist(sec, bins=np.linspace(0, 53, 53),
             histtype='step')
    plt.savefig('%s_week.png' % title, format='png')
    plt.clf()

    sec = df_['Hours'].values
    plt.hist(sec, bins=np.linspace(0, 24, 24),
             histtype='step')
    plt.savefig('%s_hour.png' % title, format='png')
    plt.clf()

    sec = df_['Weekdays'].values
    plt.hist(sec, bins=np.linspace(0, 7, 7), histtype='step')
    plt.savefig('%s_weekday.png' % title, format='png')
    plt.clf()


def local_remote_comparison(engine, table='local_remote_compare'):
    """ print out local/remote comparison for last 5 days """
    import pandas as pd
    columns = ('date', 'local', 'remote')
    cmd = "select %s " % (', '.join(columns),) + \
          "from %s " % table + \
          "where date >= current_date - interval'5 days'"
    dtm, lct, rct = [], [], []
    for line in engine.execute(cmd):
        dt_, lc_, rc_ = line
        dtm.append(dt_.strftime('%Y-%m-%dT%H:%M:%S%z'))
        lct.append(lc_)
        rct.append(rc_)
    df_ = pd.DataFrame({'Datetime': dtm, 'Local': lct, 'Remote': rct})
    print(df_.to_string(index=False))
