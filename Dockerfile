# docker pull andmyhacks/trufflehog

FROM python:2

MAINTAINER Keith Hoodlet <keith@attackdriven.io>

RUN mkdir -p /etc/trufflehog
WORKDIR /etc/trufflehog

COPY . /etc/trufflehog/

RUN apt-get update

RUN pip install truffleHog

RUN chmod +x truffleHog.py
RUN ln -s /etc/trufflehog/truffleHog.py /usr/bin/trufflehog

RUN mkdir -p /etc/trufflehog/history
WORKDIR /etc/trufflehog/history
