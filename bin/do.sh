#!/bin/bash

build_dev_container() {
    docker build -t dev -f Dockerfile.dev .
}

test_no_docker() {
    pip install -r requirements-dev.txt
    bin/test.sh
}

case $1 in
lint)
    build_dev_container
    docker run --rm -ti -v $(pwd):/app dev bash -c "black --check ."
    ;;
test-no-docker)
    test_no_docker
    ;;
test)
    build_dev_container
    docker run --rm -ti -v $(pwd):/app dev bin/test.sh
    ;;
validate-build-install)
    build_dev_container
    docker run --rm -ti -v $(pwd):/app dev bin/build_install.sh
    ;;
build-image)
    docker build -t sortigoza/trufflehog .
    ;;
*)
    echo "error no task selected"
    exit 1
    ;;
esac
