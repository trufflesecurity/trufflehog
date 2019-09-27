FROM ubuntu:bionic
ARG GIT_REPO
RUN apt-get update \
    && apt-get -y install \
        git \
        python3 \
        python2.7 \
        build-essential \
        wget \
        golang-go \
        python-pip \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN pip install gitpython
RUN pip install truffleHogRegexes
COPY . /app
WORKDIR /app

RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10
