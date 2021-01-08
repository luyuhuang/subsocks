#!/usr/bin/env bash

version=${1?"version missing"}

platforms=(
"linux amd64"
"linux 386"
"windows amd64 .exe"
"windows 386 .exe"
"darwin amd64"
)

rm -rf targets
mkdir -p targets

for p in "${platforms[@]}"; do
	eval $(echo $p | awk '{printf"os=%s;arch=%s;ext=%s",$1,$2,$3}')
	GOOS=$os GOARCH=$arch go build -ldflags "-X main.Version=$version" -o targets/subsocks-$os-$arch$ext
done

