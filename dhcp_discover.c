/*
 * Copyright 2020 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dhcp.h"

/*
  This program discovers active dhcp servers and print them to stdout
*/

static void parse_options(int argc, char** argv);
static void usage(const char* name);
static libnet_t* setup_libnet(const char* device);
static pcap_t* setup_pcap(const char* device);
static struct bootp* create_discovery_request(uint8_t* hw_addr, uint16_t* out_size);
static void send_udp_broadcast(libnet_t* libnet, uint16_t src_port, uint16_t dst_port, uint8_t* payload, uint16_t size);
static void read_dhcp_offers(pcap_t* pcap, int timeout);
static void read_dhcp_offer(struct bootp *bootp, uint32_t len);
static char* str_ip(uint32_t ip);
static char* str_hw(uint8_t* hw, int len);

const unsigned char dhcp_magic[4] = { 99, 130, 83, 99 };

// static buffer for str_ip / str_hw
char sbuffer[1024];

// options
char* device = "eth0";
int verbose = 0;
uint8_t hw_addr[6] = { 0, 0, 0, 0, 0, 1 };
int timeout = 10;

// contexts
pcap_t* pcap;

int main(int argc, char** argv) {
    parse_options(argc, argv);

    libnet_t* libnet = setup_libnet(device);
    pcap = setup_pcap(device);

    uint16_t size;
    struct bootp* discovery_request = create_discovery_request(hw_addr, &size);

    send_udp_broadcast(libnet, 68, 67, (uint8_t*) discovery_request, size);

    libnet_close_link(libnet);

    read_dhcp_offers(pcap, timeout);
    pcap_close(pcap);

    return 0;
}

static void parse_options(int argc, char** argv) {
    int c;
    while((c = getopt(argc, argv, "h:vw:")) != -1) {
        switch(c) {
            case 'h':
                sscanf(optarg, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'w':
                timeout = atoi(optarg);
                break;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        exit(2);
    }
    device = argv[optind];
}

static void usage(const char* name) {
    printf("Usage: %s [-h hwardware address] [-v] [-w timeout] interface\n", name);
    printf("Options:\n");
    printf("  -h hardware address  select hardware address to be set in dhcp discovery in hex (default 000000000001)\n");
    printf("  -v                   print lots of messages\n");
    printf("  -w timeout           sets timeout for waiting for dhcp offers in seconds (default: 10)\n\n");
    printf("interface is the name of the interface to broadcast dhcp messages.\n");
}

static libnet_t* setup_libnet(const char* device) {
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t* libnet = libnet_init(LIBNET_LINK, device, errbuf);
    if (libnet == 0) {
        fprintf(stderr, "failed to init libnet: %s\n", errbuf);
        exit(1);
    }

    return libnet;
}

static pcap_t* setup_pcap(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_create(device, errbuf);
    if (pcap == 0) {
        fprintf(stderr, "creating pcap context failed: %s\n", errbuf);
        exit(1);
    }

    if (pcap_set_promisc(pcap, 0) != 0) {
        fprintf(stderr, "setting promiscous mode to false failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_set_snaplen(pcap, 65536) != 0) {
        fprintf(stderr, "setting snaplen failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_set_buffer_size(pcap, 1024 * 1024 * 4)) {
        fprintf(stderr, "setting buffer size failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_activate(pcap) != 0) {
        fprintf(stderr, "activating pcap failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    struct bpf_program filter;
    if (pcap_compile(pcap, &filter, "udp dst port 68", 1, 0xffffffff) == -1) {
        fprintf(stderr, "compiling filter failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_setfilter(pcap, &filter) == -1) {
        fprintf(stderr, "setting filter on %s failed: %s\n", device, pcap_geterr(pcap));
        exit(1);
    }

    return pcap;
}

static struct bootp* create_discovery_request(uint8_t* hw_addr, uint16_t* out_size) {
    size_t size = sizeof(struct bootp) + 8;

    struct bootp* discovery_request = calloc(size, 1);
    discovery_request->op = 1;
    discovery_request->unused = 0x0080; // broadcast flag
    discovery_request->htype = 1;
    discovery_request->hlen = 6;
    discovery_request->xid = libnet_get_prand(LIBNET_PRu32);
    discovery_request->chaddr[0] = hw_addr[0];
    discovery_request->chaddr[1] = hw_addr[1];
    discovery_request->chaddr[2] = hw_addr[2];
    discovery_request->chaddr[3] = hw_addr[3];
    discovery_request->chaddr[4] = hw_addr[4];
    discovery_request->chaddr[5] = hw_addr[5];

    // magic cookie
    discovery_request->vend[0] = dhcp_magic[0];
    discovery_request->vend[1] = dhcp_magic[1];
    discovery_request->vend[2] = dhcp_magic[2];
    discovery_request->vend[3] = dhcp_magic[3];

    // dhcp message type
    discovery_request->vend[4] = 53; // code
    discovery_request->vend[5] = 1;  // length
    discovery_request->vend[6] = 1;  // discover

    // end of options
    discovery_request->vend[7] = (char)255;

    *out_size = (uint16_t) size;
    return discovery_request;
}

static void send_udp_broadcast(libnet_t* libnet, uint16_t src_port, uint16_t dst_port, uint8_t* payload, uint16_t size) {
    if (libnet_build_udp(src_port, dst_port, LIBNET_UDP_H + size, 0, payload, size, libnet, 0) == -1) {
        fprintf(stderr, "error building udp packet: %s\n", libnet_geterror(libnet));
        exit(1);
    }

    if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + size, 0, getpid(), 0, 64, IPPROTO_UDP, 0, 0, 0xffffffff, 0, 0, libnet, 0) == -1) {
        fprintf(stderr, "error building ip packet: %s\n", libnet_geterror(libnet));
        exit(1);
    }

    const uint8_t dst[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    if (libnet_autobuild_ethernet(dst, ETHERTYPE_IP, libnet) == -1) {
        fprintf(stderr, "error building ethernet packet: %s\n", libnet_geterror(libnet));
        exit(1);
    }

    if (libnet_write(libnet) == -1) {
        fprintf(stderr, "sending discovery request failed: %s", libnet_geterror(libnet));
        exit(1);
    }
}

static void packet_callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (verbose) {
        printf("captured %d bytes\n", pkthdr->len);
    }

    struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *) (packet + 14);
    struct libnet_udp_hdr *udp_hdr = (struct libnet_udp_hdr *) (packet + 14 + (ipv4_hdr->ip_hl << 2));

    char src_ip[16];
    char dst_ip[16];
    strcpy(src_ip, str_ip(ipv4_hdr->ip_src.s_addr));
    strcpy(dst_ip, str_ip(ipv4_hdr->ip_dst.s_addr));

    if (verbose) {
        printf("%d bytes from %s:%d to %s:%d\n", ntohs(udp_hdr->uh_ulen), src_ip, ntohs(udp_hdr->uh_sport),
               dst_ip,
               ntohs(udp_hdr->uh_dport));
    }

    if (ntohs(udp_hdr->uh_ulen) >= 8 + sizeof(struct bootp)) {
        uint32_t bootp_offset = 14 + (ipv4_hdr->ip_hl << 2) + 8;
        uint32_t len = pkthdr->len - bootp_offset;
        read_dhcp_offer((struct bootp *) (packet + bootp_offset), len);
    }
}

static void cancelPcapHandler(int sig) {
    signal(SIGALRM, SIG_IGN);
    pcap_breakloop(pcap);
}

static void read_dhcp_offers(pcap_t* pcap, int wait) {
    // ideally select + non-blocking pcap could be used here but this causes packet drops:
    // https://github.com/the-tcpdump-group/libpcap/issues/169

    signal(SIGALRM, cancelPcapHandler);
    alarm(wait);

    // Loop:
    pcap_loop(pcap, -1, packet_callback, 0);
}

static void read_dhcp_offer(struct bootp *bootp, uint32_t len) {
    if (memcmp(dhcp_magic, bootp->vend, sizeof(dhcp_magic)) != 0) {
        fprintf(stderr, "not a bootp packet");
        return;
    }

    if (verbose) {
        printf("packet op code / message type: %d\n", bootp->op);
        printf("hardware address type: %d\n", bootp->htype);
        printf("hardware address length: %d\n", bootp->hlen);
        printf("hops: %d\n", bootp->hops);
        printf("transaction id: %d\n", bootp->xid);
        printf("seconds elapsed since boot: %d\n", bootp->secs);
        printf("client ip address: %s\n", str_ip(bootp->ciaddr));
        printf("your ip address: %s\n", str_ip(bootp->yiaddr));
        printf("server ip address: %s\n", str_ip(bootp->siaddr));
        printf("gateway ip address: %s\n", str_ip(bootp->giaddr));
    }

    if (bootp->hlen > 16) {
        fprintf(stderr, "malformed bootp message: client hardware address length %d > 16 bytes", bootp->hlen);
        return;
    }
    if (verbose) {
        printf("client hardware address: %s\n", str_hw(bootp->chaddr, bootp->hlen));
    }

    if (strnlen(bootp->sname, sizeof(bootp->sname)) == sizeof(bootp->sname)) {
        fprintf(stderr, "malformaed bootp message: server host name is not null-terminated\n");
    }
    if (verbose) {
        printf("server host name: %s\n", bootp->sname);
    }

    if (strnlen(bootp->file, sizeof(bootp->file)) == sizeof(bootp->file)) {
        fprintf(stderr, "malformaed bootp message: boot file name is not null-terminated\n");
    }
    if (verbose) {
        printf("boot file name: %s\n", bootp->file);
    }

    // ignore non-replies
    if (bootp->op != 2) {
        return;
    }

    // read dhcp options
    uint8_t message_type = 0;
    uint32_t server_id = 0;
    uint32_t subnet = 0;

    uint32_t i = 4;
    while(i < len) {
        uint8_t code = (uint8_t) bootp->vend[i++];

        if (code == 255) {
            break;
        }

        if (code == 0) {
            continue;
        }

        if (i == len) {
            fprintf(stderr, "options out-of-bound\n");
            return;
        }

        uint8_t option_length = 0;
        option_length = (uint8_t) bootp->vend[i++];

        if (i + option_length >= len) {
            fprintf(stderr, "options out-of-bound\n");
            return;
        }

        if (code == 1) {
            if (option_length != 4) {
                fprintf(stderr, "expected 4 bytes for subnet mask option (1)\n");
                return;
            }
            subnet = (uint8_t) bootp->vend[i] | (uint8_t) bootp->vend[i + 1] << 8 | (uint8_t) bootp->vend[i + 2] << 16 |
                     (uint8_t) bootp->vend[i + 3] << 24;
            if (verbose) {
                printf("offset: %d vendor option: %d length: %d subnet mask: %s\n", i, code, option_length,
                       str_ip(subnet));
            }
        } else if (code == 53) {
            if (option_length != 1) {
                fprintf(stderr, "expected 1 byte for dhcp message type option (53)\n");
            }
            message_type = bootp->vend[i];
            if (verbose) {
                printf("offset: %d vendor option: %d length: %d message type: %d\n", i, code, option_length,
                       message_type);
            }
        } else if (code == 54) {
            if (option_length != 4) {
                fprintf(stderr, "expected 4 bytes for server identifier option (54)\n");
                return;
            }
            server_id = (uint8_t) bootp->vend[i] | (uint8_t) bootp->vend[i + 1] << 8 | (uint8_t) bootp->vend[i + 2] << 16 |
                        (uint8_t) bootp->vend[i + 3] << 24;
            if (verbose) {
                printf("offset: %d vendor option: %d length: %d server identifier: %s\n", i, code, option_length,
                       str_ip(server_id));
            }
        } else if (verbose) {
            printf("offset: %d vendor option: %d length: %d\n", i, code, option_length);
        }

        i += option_length;
    }

    if (message_type != 2) {
        return;
    }

    char sserver_ip[16];
    char sclient_ip[16];
    char ssubnet_mask[16];
    strcpy(sserver_ip, str_ip(server_id));
    strcpy(sclient_ip, str_ip(bootp->yiaddr));
    strcpy(ssubnet_mask, str_ip(subnet));
    printf("offer from %s: %s / %s\n", sserver_ip, sclient_ip, ssubnet_mask);
}

static char* str_ip(uint32_t ip) {
    sprintf(sbuffer, "%d.%d.%d.%d", ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff);
    return sbuffer;
}

static char* str_hw(uint8_t* hw, int len) {
    int i;
    for (i = 0; i < len; ++i) {
        sprintf(sbuffer + i * 2, "%02x", hw[i]);
    }
    return sbuffer;
}