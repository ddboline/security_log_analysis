#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Created on Sun May 17 07:14:20 2015

@author: ddboline
"""
from __future__ import (absolute_import, division, print_function)
import sys
from setuptools import setup

console_scripts = (('security-log-parse', 'security_log_analysis.cli:run_parse'),
                   ('security-log-analyze', 'security_log_analysis.cli:run_analyze'))

if sys.version_info.major == 2:
    console_scripts = ['%s = %s' % (x, y) for x, y in console_scripts]
else:
    v = sys.version_info.major
    console_scripts = ['%s%s = %s' % (x, v, y) for x, y in console_scripts]

setup(
    name='security_log_analysis',
    version='0.0.3.9',
    author='Daniel Boline',
    author_email='ddboline@gmail.com',
    description='security_log_analysis',
    long_description='Garmin App',
    license='MIT',
    test_suite='nose.collector',
    install_requires=['sqlalchemy'],
    packages=['security_log_analysis'],
    package_dir={'security_log_analysis': 'security_log_analysis'},
    package_data={'security_log_analysis': ['templates/*.html']},
    entry_points={
        'console_scripts': console_scripts
    })
