#!/bin/bash

sudo apt-get update
sudo apt-get install -y whois
sudo /opt/conda/bin/conda install -c https://conda.anaconda.org/ddboline --yes requests \
    pandas python-dateutil matplotlib boto psycopg2 sqlalchemy pytest coverage pytest-cov
