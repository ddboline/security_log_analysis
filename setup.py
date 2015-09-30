#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Created on Sun May 17 07:14:20 2015

@author: ddboline
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
#from __future__ import unicode_literals

from setuptools import setup

setup(
    name='security_log_analysis',
    version='00.00.01',
    author='Daniel Boline',
    author_email='ddboline@gmail.com',
    description='security_log_analysis',
    long_description='Garmin App',
    license='MIT',
    install_requires=['pandas', 'numpy', 'requests', 'sqlalchemy', 'pyusb'],
    packages=['security_log_analysis'],
    package_dir={'security_log_analysis': 'security_log_analysis'},
    entry_points={'console_scripts':
                    ['security_log_parse = security_log_analysis.cli:run']}
)
