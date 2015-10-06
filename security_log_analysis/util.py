#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Mon Jun  1 18:32:18 2015

@author: ddboline
"""

import os
from subprocess import Popen
import shlex
import time
from sqlalchemy import create_engine

HOSTNAME = os.uname()[1]


class OpenPostgreSQLsshTunnel(object):
    """ Class to let us open an ssh tunnel, then close it when done """
    def __init__(self):
        self.tunnel_process = 0
        self.postgre_port = 5432

    def __enter__(self):
        if HOSTNAME != 'dilepton-tower':
            self.postgre_port = 5436
            _cmd = 'ssh -N -L localhost:' + self.postgre_port + \
                   ':localhost:5432 ddboline@ddbolineathome.mooo.com'
            args = shlex.split(_cmd)
            self.tunnel_process = Popen(args, shell=False)
            time.sleep(5)
        return self.postgre_port

    def __exit__(self, exc_type, exc_value, traceback):
        if self.tunnel_process:
            self.tunnel_process.kill()
        if exc_type or exc_value or traceback:
            return False
        else:
            return True


def create_db_engine(port=5432, dbname='ssh_intrusion_logs'):
    """ Create sqlalchemy database engine """
    user = 'ddboline'
    pwd = 'BQGIvkKFZPejrKvX'
    host = 'localhost'
    dbstring = 'postgresql://%s:%s@%s:%s/%s' % (user, pwd, host, port, dbname)
    engine = create_engine(dbstring)
    return engine
