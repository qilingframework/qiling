FROM python:3.6-alpine

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV PIP_NO_CACHE_DIR=1

RUN apk add --no-cache \
    gcc \
    make \
    cmake \
    libtool \
    automake \
    autoconf \
    libmagic \
    g++ \
    linux-headers \
    git \
    libstdc++ \
    bash \
    vim

RUN git clone -b dev https://github.com/qilingframework/qiling.git \
    && cd qiling \
    && pip3 install . \ 
    && rm -rf /tmp/*

WORKDIR /qiling

ENV HOME /qiling

CMD bash
