#ifndef DHCP_HEADER

#include <stdint.h>

// bootp packet format as defined in RFC 951 https://tools.ietf.org/html/rfc951

struct bootp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t unused;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    char sname[64];
    char file[128];
    char vend[];
} __attribute__((__packed__));

#endif