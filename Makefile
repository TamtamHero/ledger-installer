all:

install:
	go install github.com/kompose-app/ledger-installer/cmd/...

.PHONY: image push

GIT_HASH := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
IMAGE_NAME := "docker.direct/kompose/ledger-installer"
CURRDIR=$(PWD)

image:
	docker build --build-arg GIT_HASH=$(GIT_HASH) -t $(IMAGE_NAME):local .
	docker tag $(IMAGE_NAME):local $(IMAGE_NAME):$(GIT_HASH)
	docker tag $(IMAGE_NAME):local $(IMAGE_NAME):latest

push:
	docker push $(IMAGE_NAME):$(GIT_HASH)
	docker push $(IMAGE_NAME):latest

restart-%:
	docker-compose stop $*
	docker-compose up -d --no-deps --build $*
