FROM python:2-alpine
RUN apk add --no-cache git && pip install trufflehog
WORKDIR /proj
ENTRYPOINT [ "trufflehog" ]
CMD [ "-h" ]
