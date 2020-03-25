FROM ubuntu:18.04

MAINTAINER "Kevin Foo <chbsd64@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y python3-pip git vim.tiny cmake \
  && git clone https://github.com/qilingframework/qiling.git 

WORKDIR /qiling

RUN pip3 install -r requirements.txt \
  && python3 setup.py install

RUN pysite1=$(python3 -c "import site; print(site.getsitepackages()[0])"); \
  pysite2=$(python3 -c "import site; print(site.getsitepackages()[1])")\
  && cp ${pysite1}${pysite2}/keystone/libkeystone.so $pysite1/keystone/

RUN apt-get install -y vim
RUN apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV HOME /qiling

EXPOSE 9999

CMD bash

