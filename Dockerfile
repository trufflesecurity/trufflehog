FROM python:3-alpine as builder

COPY . .
RUN python3 setup.py bdist_wheel -d dist

FROM python:3-alpine

WORKDIR /proj

RUN apk add -q --no-cache git \
    && adduser -S truffleHog

COPY --from=builder dist/truffleHog-3.0.0-py2.py3-none-any.whl /tmp/
RUN pip install /tmp/truffleHog-3.0.0-py2.py3-none-any.whl \
    && trufflehog -h

USER truffleHog
ENTRYPOINT [ "trufflehog" ]
CMD [ "-h" ]
