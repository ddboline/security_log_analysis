#!/bin/bash

nosetests --with-coverage --cover-package=security_log_analysis ./tests/*.py security_log_analysis/*.py
