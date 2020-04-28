## ledger-installer

### Installation

```
docker pull docker.direct/kompose/ledger-installer:latest
```

### Running

See [docker-compose.yaml](/docker-compose.yaml)

Example artifacts layout:
```
└── artifacts
    └── klaytn_ce
        ├── blue_v1.0.0
        │   ├── bin
        │   │   └── app.hex
        │   └── manifest.json
        ├── nanos_v1.0.0
        │   ├── bin
        │   │   └── app.hex
        │   └── manifest.json
        └── nanox_v1.0.0
            ├── bin
            │   └── app.hex
            └── manifest.json
```

### API

#### App Info

Endpoint:
`/api/v1/appInfo`

Params:

* `name`
* `version`

Example:
```
$ curl http://localhost:8080/api/v1/appInfo/klaytn_ce/nanos_v1.0.0

{
    "name": "Klaytn CE",
    "version": "1.0.0",
    "icon": "010000000000ffffffffffffff7ffcbff89ff04fe847c443c223c3a3c467e82ff01ff87ffeffffffff",
    "targetId": "0x31100004",
    "targetVersion": "1.6.0",
    "signature": "",
    "flags": "0xa40",
    "derivationPath": {
        "curves": [
            "secp256k1"
        ],
        "paths": [
            "44'/8217'"
        ]
    },
    "binary": "bin/app.hex",
    "dataSize": 64
}
```

#### App Install

Endpoint:
`/api/v1/appInstall`

Params:

* `name`
* `version`

Example:
```
$ curl -X POST http://localhost:8080/api/v1/appInstall/klaytn_ce/nanos_v1.0.0

e00400000431100004
...
```

You should actually deliver those lines to Ledger via U2F and forward responses back to the streaming request body.

This endpoint supports WebSockets API:

```
ws://localhost:8080/apiws/v1/appInstall/klaytn_ce/nanos_v1.0.0
```

For use in browsers that cannot make a streaming POST request.

### License

[Apache License 2.0](/LICENSE)
