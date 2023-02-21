Zeek CAPWAP packet analyzer
=================================

This repository contains a [Zeek](https://zeek.org/) packet analyzer for the [CAPWAP](https://en.wikipedia.org/wiki/CAPWAP) protocol. Mainly focus on data channel (port 5247). It is packed as a Zeek package, which can be easily installed with [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/).

The CAPWAP protocol is defined in the following RFCs:
- CAPWAP: [RFC 5415](https://datatracker.ietf.org/doc/html/rfc5415)
- CAPWAP IEEE 802.11 binding : [RFC 5416](https://datatracker.ietf.org/doc/html/rfc5416)


## Installation

### Prerequisites

Before trying to install the package, make sure you have the following tools installed:

- [Zeek](https://zeek.org/)
- [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/) command `zkg`

Everything should be installed correctly if you install the latest [Zeek](https://zeek.org/) version.


### Setup

A simple call to `make install` from the repository's root directory should install the package and run unit tests.
You can also use the `zkg` command directly:
```shell
zkg install https://github.com/AmazingPP/zeek-capwap  # to install as super user
zkg --user install https://github.com/AmazingPP/zeek-capwap  # to install in user space
```

You might have to update the `ZEEKPATH` and `ZEEK_PLUGIN_PATH` environmental variables.
To see which value they should take, run the following commands:
```shell
zkg env         # For the super user
zkg --user env  # For a normal user
```

To confirm that installation was successful, you can run the following command:
```shell
zeek -NN | grep CAPWAP
```

If the command's output shows something similar to:
```
[Packet Analyzer] CAPWAP (ANALYZER_CAPWAP)
```
the package was correctly installed, and you have access to the CAPWAP packet analyzer.

In the case of any installation problems, please check the [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/) documentation.

### Events

The plugin defines the following events:
- `event capwap_packet(outer: connection, inner: pkt_hdr)`
  - Generated for any packet encapsulated in a CAPWAP tunnel.

## License

This project is licensed under the BSD license. See the [LICENSE](LICENSE) file for details.

## Contributors

- Fupeng Zhao
  - GitHub: [@AmazingPP](https://github.com/AmazingPP)
  - Email: fupeng.zhao@foxmail.com
