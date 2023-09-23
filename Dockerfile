FROM python:3-slim AS base

WORKDIR /qiling

# hadolint global ignore=DL3008,DL3013
ENV DEBIAN_FRONTEND=noninteractive
ENV AM_I_IN_A_DOCKER_CONTAINER=True

RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*


FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
	cmake build-essential gcc git \
	&& rm -rf /var/lib/apt/lists/*

COPY pyproject.toml poetry.lock ./
RUN pip3 install --no-cache-dir poetry \
	&& poetry install --no-root --no-directory

COPY qiling/ tests/ examples/ ./
RUN poetry install --no-dev && poetry build --format=wheel

FROM base

LABEL maintainer="Kevin Foo <chfl4gs@qiling.io>"

COPY --from=builder /qiling /qiling

WORKDIR /qiling

RUN apt-get update \
	&& apt-get install -y --no-install-recommends unzip apt-utils \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip3 install --no-deps --no-cache-dir dist/*.whl \
	&& rm -rf ./dist/

CMD ["bash"]
