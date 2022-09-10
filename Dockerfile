FROM python:3.8-slim AS builder

LABEL maintainer="Kevin Foo <chfl4gs@qiling.io>"

ENV DEBIAN_FRONTEND=noninteractive
ENV AM_I_IN_A_DOCKER_CONTAINER Yes

RUN apt-get update \
  && apt-get -y upgrade \
  && apt-get install -y --no-install-recommends cmake build-essential gcc git

COPY . /qiling

RUN cd /qiling \
  && pip wheel . -w wheels

FROM python:3.8-slim AS base

COPY --from=builder /qiling /qiling

WORKDIR /qiling

RUN apt-get update \
  && apt-get install -y --no-install-recommends unzip apt-utils \
  && rm -rf /var/lib/apt/lists/* \
  && pip3 install --no-deps wheels/*.whl \
  && rm -rf wheels

ENV HOME /qiling

CMD bash
