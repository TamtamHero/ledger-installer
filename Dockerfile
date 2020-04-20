# build server in seperate image

FROM golang:1.14-alpine as gobuilder

RUN apk add --no-cache git gcc libc-dev

WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go install github.com/kompose-app/ledger-installer/cmd/...

FROM python:3.7-alpine as base

# getting requirements for the python app

FROM base as pybuilder
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --install-option="--prefix=/install" -r /requirements.txt

FROM base

# install server binary into system

RUN apk add --update --no-cache ca-certificates
COPY --from=gobuilder /go/bin/* /usr/local/bin/

# install python app into /app

FROM base
COPY --from=pybuilder /install /usr/local
COPY app /app

# define env vars

ENV APP_ENV=local
ENV APP_LOG_LEVEL=info
ENV APP_BUGSNAG_KEY=""
ENV APP_ARTIFACTS_PATH=/artifacts
ENV APP_INSTALLER_PATH="/app/ledgerInstaller.py"
ENV HTTP_LISTEN_ADDR="localhost:8080"

# vmount for prepared ledger artifacts

VOLUME /artifacts

# run config

EXPOSE 8080

CMD ["ledger-installer"]
