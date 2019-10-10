FROM ubuntu:18.04 AS builder

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/src

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python make cmake build-essential gcc git

RUN git clone https://github.com/unicorn-engine/unicorn \
  && cd unicorn \
  && ./make.sh

WORKDIR /usr/src

RUN git clone https://github.com/qilingframework/qiling

FROM ubuntu:18.04

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python3-pip python \
  && pip3 install wheel capstone keystone-engine python-registry lief==0.10.0.dev0 pefile>=2019.4.18

COPY --from=builder /usr/src/qiling /qiling
COPY --from=builder /usr/src/unicorn /tmp/unicorn

RUN cd /tmp/unicorn \
  && ./make.sh install \
  && cd bindings/python \
  && python3 setup.py install

RUN cd /qiling \
  && python3 setup.py install

RUN apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV HOME /qiling

WORKDIR /qiling

CMD bash