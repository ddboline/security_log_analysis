#!/bin/bash

### hack...
export LANG="C.UTF-8"

sudo bash -c "echo deb ssh://ddboline@home.ddboline.net/var/www/html/deb/trusty/python3/devel ./ > /etc/apt/sources.list.d/py2deb2.list"
sudo apt-get update
sudo apt-get install -y --force-yes python3-pandas python3-dateutil python3-usb \
                                    python3-psycopg2 python3-sqlalchemy python3-pytest \
                                    python3-coverage python3-numpy python3-pandas whois \
                                    python3-pytest python3-setuptools python3-dev python3-pytest-cov
