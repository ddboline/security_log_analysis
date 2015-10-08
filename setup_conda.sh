#!/bin/bash

sudo apt-get update
sudo /opt/conda/bin/conda install -c https://conda.anaconda.org/ddboline --yes requests \
    pandas dateutil matplotlib boto psycopg2 sqlalchemy nose coverage
