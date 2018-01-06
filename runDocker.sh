docker run --name flaskapp --restart=always \
    -p 8080:8080 \
    -v web/:web/ \
    -d jazzdd/alpine-flask
