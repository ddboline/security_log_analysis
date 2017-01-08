#!/bin/bash

sudo apt-get update
sudo apt-get install -y --force-yes python-pandas python-dateutil python-usb \
                                    python-psycopg2 python-sqlalchemy python-pytest \
                                    python-coverage python-numpy python-pandas whois \
                                    python-pytest python-setuptools python-dev python-pytest-cov
