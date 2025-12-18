FROM ubuntu:25.04

RUN apt-get update && apt-get install -y
#RUN apt-get install -y git make gcc g++ zlib1g-dev libpcre3-dev nano

#RUN apt-get install -y git make gcc g++ zlib1g-dev libpcre3-dev nano build-essential zlib1g-dev mysql-client mysql-server
RUN apt-get install -y git make libmariadb-dev libmysqlclient-dev libmariadbclient-dev-compat gcc g++ zlib1g-dev libpcre3-dev

ENTRYPOINT ["/home/startDocker.sh"]

