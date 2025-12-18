#!/bin/bash

#apt update && apt install -y
#apt-get update

apt-get update && apt-get install -y
apt-get install -y git make gcc g++ zlib1g-dev libpcre3-dev nano build-essential zlib1g-dev mysql-client mysql-server
apt-get install -y git make libmariadb-dev libmysqlclient-dev libmariadbclient-dev-compat gcc g++ zlib1g-dev libpcre3-dev
sh ./configure
make clean
make server
chmod a+x login-server && chmod a+x char-server && chmod a+x map-server && chmod a+x web-server
./configure && make clean && make server
