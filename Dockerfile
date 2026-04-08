FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV MAKEFLAGS=-j1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        iproute2 \
        libmariadb-dev \
        libmariadb-dev-compat \
        libssl-dev \
        libpcre3-dev \
        mariadb-client \
        procps \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/rathena

COPY . .

RUN chmod +x startDocker.sh \
    && ./configure CFLAGS="-O1 -g0" \
    && make clean \
    && make server

EXPOSE 6900 6121 5121

ENTRYPOINT ["./startDocker.sh"]
