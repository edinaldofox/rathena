FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        libmariadb-dev \
        libmariadb-dev-compat \
        libpcre3-dev \
        mariadb-client \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/rathena

COPY . .

RUN chmod +x startDocker.sh \
    && ./configure \
    && make clean \
    && make server

EXPOSE 6900 6121 5121

ENTRYPOINT ["./startDocker.sh"]
