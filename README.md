## Overview

This library implements request signing using the [AWS Signature
Version 4][aws4] specification. This signature scheme is used by nearly all AWS
services, but the current focus is on signing S3 GET requests.

[aws4]: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

## Usage

See ```haproxy.cfg``` for an example

## Demo

Start it up with docker-compose
```
$ docker-compose up
```

Configure minio-client
```
$ mc alias set minio http://localhost:9000/ "AKIAIOSFODNN7EXAMPLE" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Create the test bucket
```
$ mc mb minio/test
```

Copy some files into the test bucket
```
$ mc cp test.txt minio/test
```

Profit
```
$ curl localhost:8080/test.txt
It works!
```