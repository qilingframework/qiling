FROM ubuntu:18.04

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python3-pip git cmake

WORKDIR /

RUN git clone https://github.com/qilingframework/qiling

RUN cd /qiling \
  && pip3 install -r requirements.txt
  && python3 setup.py install

RUN apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV HOME /qiling

WORKDIR /qiling

CMD bash
