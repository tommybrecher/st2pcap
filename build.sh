#!/bin/bash
set -e

echo "Building st2pcap for macOS..."
GOOS=darwin GOARCH=amd64 go build -o st2pcap_amd64
GOOS=darwin GOARCH=arm64 go build -o st2pcap_arm64
lipo -create -output st2pcap st2pcap_amd64 st2pcap_arm64
