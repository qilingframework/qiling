FROM ubuntu:18.04

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python3-pip git cmake

WORKDIR /

RUN git clone https://github.com/t14g0p/qiling

RUN cd /qiling \
  && pip3 install -r requirements.txt \
  && python3 setup.py install

RUN apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#Fix keystone pip3 install of the lib in the wrong dir 
RUN cp /usr/local/lib/python3.6/dist-packages/usr/lib/python3/dist-packages/keystone/libkeystone.so /usr/local/lib/python3.6/dist-packages/keystone/

ENV HOME /qiling

WORKDIR /qiling

CMD bash
