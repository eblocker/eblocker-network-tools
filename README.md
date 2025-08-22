# eblocker-network-tools

Network components written in C.

## Prerequisites

Install required libraries:

    sudo apt-get install libnet1-dev libpcap-dev libhiredis-dev

Create the group `icapd`:

    addgroup icapd

## Build

Build a Debian package:

    make package

## Test

### DHCP discovery

Run DHCP discovery for 10 seconds:

    sudo ./dhcp_discover -w 10 -h 123456abcdef eth0

If a DHCP service runs in your network you should see an output similar to:

    offer from 192.168.2.1: 192.168.2.125 / 255.255.255.0
