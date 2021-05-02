FROM python:3-alpine
RUN apk add --no-cache git && pip install gitdb2==3.0.0 GitPython==3.0.6 truffleHogRegexes==0.0.7
COPY truffleHog/truffleHog.py /usr/local/bin/trufflehog
WORKDIR /proj
ENTRYPOINT [ "trufflehog" ]
CMD [ "-h" ]
