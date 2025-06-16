# st2pcap

[![Build and Release](https://github.com/tommybrecher/st2pcap/actions/workflows/release.yml/badge.svg)](https://github.com/tommybrecher/st2pcap/actions/workflows/release.yml)

Converts SIPTrace logs to PCAP files for easy analysis in Wireshark or other network tools.

## Features

- Parses SIPTrace log files
- Outputs valid PCAP files with SIP messages as UDP packets
- Supports macOS (darwin, amd64/arm64)
- GitHub Actions CI for build and release

## Usage

```bash
st2pcap -input <siptrace.log> -output <output.pcap>
```

- `-input`: Path to the SIPTrace log file
- `-output`: Path to the output PCAP file

## Build

To build locally:

```bash
go build -o st2pcap .
```

## GitHub Actions

On tags starting with `v`, the project is built for macOS (amd64/arm64) and release artifacts are published automatically.

## License

MIT
