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
    g++ \
    linux-headers \
    git \
    libstdc++ \
    bash \
    vim 

RUN git clone https://github.com/qilingframework/qiling.git \
    && cd qiling \
    && pip3 install -r requirements.txt \
    && python3 setup.py install \ 
    && pysite=$(python3 -c "import site; print(site.getsitepackages()[0])"); \
    cp ${pysite}${pysite}/keystone/libkeystone.so ${pysite}/keystone/ \
    && rm -rf /tmp/*

WORKDIR /qiling

ENV HOME /qiling

CMD bash
