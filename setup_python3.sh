#!/bin/bash

### hack...
export LANG="C.UTF-8"

sudo apt-get update
sudo apt-get install -y python3-requests \
                        python3-psycopg2 python3-sqlalchemy \
                        python3-nose python3-coverage
