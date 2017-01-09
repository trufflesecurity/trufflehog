FROM alpine:3.4
MAINTAINER @dxa4481

RUN apk add -U \
    git==2.8.3-r0 \
    python==2.7.12-r0 \
    py-pip==8.1.2-r0 \
    openssh-client==7.2_p2-r4

COPY app/ /app/

RUN pip install -r /app/requirements.txt

ENTRYPOINT ["python", "/app/truffleHog.py"]
