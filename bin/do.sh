#!/bin/bash

build_dev_container() {
    docker build -t dev -f Dockerfile.dev .
}

test_no_docker() {
    pip install -r requirements-dev.txt
    bin/test.sh
}

function helptext() {
    echo "Usage: ./bin/do.sh <command>"
    echo ""
    echo "Available commands are:"
    echo "    lint                    "
    echo "    test-no-docker          "
    echo "    test                    "
    echo "    validate-build-install  "
    echo "    build-image             "
    echo "    type-check              "
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
type-check)
    mypy --ignore-missing-imports truffleHog
    ;;
*)
    helptext
    echo "error no task selected"
    exit 1
    ;;
esac
