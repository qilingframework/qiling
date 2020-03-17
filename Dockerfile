FROM ubuntu:18.04

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python3-pip git cmake\
  && apt-get install -y vim

COPY ./requirements.txt ./qiling/requirements.txt
RUN pip3 install -r /qiling/requirements.txt



RUN pysite1=$(python3 -c "import site; print(site.getsitepackages()[0])"); \
  pysite2=$(python3 -c "import site; print(site.getsitepackages()[1])")\
  && cp ${pysite1}${pysite2}/keystone/libkeystone.so $pysite1/keystone/

RUN apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV HOME /qiling

WORKDIR /qiling

CMD bash
