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
#include <pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <hiredis/hiredis.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "dhcp.h"
#include "nd_ext.h"

/*
  This program listens for ARP packets and publishes them in the Redis channel "arp:in".

  The message format is described in arp_write.c
*/

char message[1024];
pcap_t* context = NULL;
bool retry = false;
unsigned int sleep_duration = 10;

void process_arp_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ip_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_icmpv6_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void packet_callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->caplen < ETHER_HDR_LEN) {
        fprintf(stderr, "Packet length less than ethernet header length\n");
        return;
    }

    redisContext* redis_ctx = (redisContext*) args;

    struct ether_header* ether_hdr = (struct ether_header *) packet;
    u_short type = ntohs(ether_hdr->ether_type);
    switch(type) {
    case ETHERTYPE_ARP:
        process_arp_packet(redis_ctx, pkthdr, packet);
        break;
    case ETHERTYPE_IP:
        process_ip_packet(redis_ctx, pkthdr, packet);
        break;
    case ETHERTYPE_IPV6:
        process_icmpv6_packet(redis_ctx, pkthdr, packet);
        break;
    default:
        fprintf(stderr, "Expected to receive only ARP or IP packets\n");
        return;
    }
}

void redisPublish(redisContext* redis_ctx, const char* channel, const char* message) {
    printf("Channel: %s Message: %s\n", channel, message);
    redisReply* reply = redisCommand(redis_ctx, "publish %s %s", channel, message);
    if (reply == NULL) {
        fprintf(stderr, "Failed to publish message to redis\n");
        retry = true;
        pcap_breakloop(context);
        return;
    }
    freeReplyObject(reply);
}

// Processes an ARP packet
void process_arp_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    if (pkthdr->caplen >= sizeof(struct ether_header) + sizeof(struct ether_arp)) {
        struct ether_arp* arp = (struct ether_arp*) (packet + sizeof(struct ether_header));

        u_int8_t* source_mac = arp->arp_sha;
        u_int8_t* source_ip  = arp->arp_spa;
        u_int8_t* target_mac = arp->arp_tha;
        u_int8_t* target_ip  = arp->arp_tpa;

        unsigned short int operation = ntohs(arp->arp_op);

        sprintf(message,
                "%hu/%02x%02x%02x%02x%02x%02x/%d.%d.%d.%d/%02x%02x%02x%02x%02x%02x/%d.%d.%d.%d",
                operation,
                source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5],
                source_ip[0], source_ip[1], source_ip[2], source_ip[3],
                target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5],
                target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

        /* Store MAC -> IP in Redis: */
        redisPublish(redis_ctx, "arp:in", message);
    }
}

void process_ip_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->caplen >= sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bootp)) {
        struct iphdr* iphdr = (struct iphdr*) (packet + sizeof(struct ether_header));
        // ignore non broadcast packets
        if (iphdr->saddr != 0 || iphdr->daddr != 0xffffffff) {
            return;
        }

        struct bootp* bootp = (struct bootp*) (packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
        // ignore non-dhcp packets
        if (bootp->vend[0] != 0x63 || bootp->vend[1] != (char) 0x82 || bootp->vend[2] != 0x53 || bootp->vend[3] != 0x63) {
            return;
        }

        // ignore replies
        if (bootp->op != 1) {
            return;
        }

        sprintf(message, "1/%02x%02x%02x%02x%02x%02x", bootp->chaddr[0], bootp->chaddr[1], bootp->chaddr[2], bootp->chaddr[3], bootp->chaddr[4], bootp->chaddr[5]);
        redisPublish(redis_ctx, "dhcp:in", message);
    }
}

struct sb {
    char* buffer;
    size_t length;
    size_t max_length;
    int overflow;
};

struct sb* sb_new(size_t max_length) {
    struct sb* sb = malloc(sizeof(struct sb));
    sb->length = 0;
    sb->max_length = max_length;
    sb->buffer = calloc(max_length, sizeof(char));
    sb->overflow = 0;
    return sb;
}

void sb_free(struct sb* sb) {
    free(sb->buffer);
    free(sb);
}

void sb_printf(struct sb* sb, const char* fmt, ...) {
    if (sb->overflow) {
        return;
    }

    size_t n = sb->max_length - sb->length;
    va_list argp;
    va_start(argp, fmt);
    int write = vsnprintf(sb->buffer + sb->length, n, fmt, argp);
    va_end(argp);

    if (write >= n) {
        fprintf(stderr, "sb exhausted\n");
        sb->overflow = 1;
    } else {
        sb->length += write;
    }
}

void sb_print_hex(struct sb* sb, const uint8_t* data, int len) {
    if (sb->overflow) {
        return;
    }

    int i;
    for (i = 0; i < len; ++i) {
        size_t n = sb->max_length - sb->length;
        if (n < 3) {
            fprintf(stderr, "sb exhausted\n");
            sb->overflow = 1;
            return;
        }
        sprintf(sb->buffer + sb->length, "%02x", data[i]);
        sb->length += 2;
    }
}

void sb_print_router_advert_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void sb_print_neighbor_advert_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void sb_print_neighbor_solicit_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void process_icmpv6_packet(redisContext* redis_ctx, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // ignore too short packets
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
        return;
    }

    // ignore too large packets
    if (pkthdr->caplen >= 65536) {
        return;
    }

    struct ether_header* ether_header = (struct ether_header*) packet;
    struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) (packet + sizeof(struct ether_header));
    struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

    // accept ping / nd packets
    int parse_nd_options = 0;
    switch(icmp6_hdr->icmp6_type) {
    case ND_ROUTER_ADVERT:
    case ND_ROUTER_SOLICIT:
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
        parse_nd_options = 1;
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        break;
    default:
        return;
    }

    // link-level and ipv6 source / target
    struct sb* sb = sb_new(1024);
    sb_print_hex(sb, ether_header->ether_shost, 6);
    sb_printf(sb, "/");
    sb_print_hex(sb, ip6_hdr->ip6_src.__in6_u.__u6_addr8, 16);
    sb_printf(sb, "/");
    sb_print_hex(sb, ether_header->ether_dhost, 6);
    sb_printf(sb, "/");
    sb_print_hex(sb, ip6_hdr->ip6_dst.__in6_u.__u6_addr8, 16);
    sb_printf(sb, "/icmp6/%i", icmp6_hdr->icmp6_type);

    // icmp type specific options
    size_t nd_option_offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr);
    switch(icmp6_hdr->icmp6_type) {
    case ND_ROUTER_ADVERT:
        sb_print_router_advert_info(sb, pkthdr, packet);
        nd_option_offset += sizeof(struct nd_router_advert);
        break;
    case ND_NEIGHBOR_ADVERT:
        sb_print_neighbor_advert_info(sb, pkthdr, packet);
        nd_option_offset += sizeof(struct nd_neighbor_advert);
        break;
    case ND_NEIGHBOR_SOLICIT:
        sb_print_neighbor_solicit_info(sb, pkthdr, packet);
        nd_option_offset += sizeof(struct nd_neighbor_solicit);
        break;
    case ND_ROUTER_SOLICIT:
        nd_option_offset += sizeof(struct nd_router_solicit);
        break;
    default:
        break;
    }

    // optionally parse and append nd-options
    if (parse_nd_options) {
        while (pkthdr->caplen >= nd_option_offset + sizeof(struct nd_opt_hdr)) {
            struct nd_opt_hdr* nd_opt_hdr = (struct nd_opt_hdr*) (packet + nd_option_offset);
            if (nd_opt_hdr->nd_opt_len == 0 || pkthdr->caplen < nd_option_offset + nd_opt_hdr->nd_opt_len * 8) {
                fprintf(stderr, "insufficient packet length\n");
                break;
            }

            struct nd_opt_prefix_info* nd_opt_prefix_info;
            struct nd_opt_rdns* nd_opt_rdns;
            struct nd_opt_mtu* nd_opt_mtu;
            int rdns;
            switch (nd_opt_hdr->nd_opt_type) {
            case ND_OPT_SOURCE_LINKADDR:
            case ND_OPT_TARGET_LINKADDR:
                sb_printf(sb, "/%i/", nd_opt_hdr->nd_opt_type);
                sb_print_hex(sb, packet + nd_option_offset + 2, 6);
                break;
            case ND_OPT_PREFIX_INFORMATION:
                nd_opt_prefix_info = (struct nd_opt_prefix_info*) (packet + nd_option_offset);
                sb_printf(sb,
                          "/%i/%u/%u/%u/%u/%u/",
                          ND_OPT_PREFIX_INFORMATION,
                          nd_opt_prefix_info->nd_opt_pi_prefix_len,
                          nd_opt_prefix_info->nd_opt_pi_flags_reserved >> 7,
                          nd_opt_prefix_info->nd_opt_pi_flags_reserved >> 6 & 1,
                          ntohl(nd_opt_prefix_info->nd_opt_pi_valid_time),
                          ntohl(nd_opt_prefix_info->nd_opt_pi_preferred_time));
                sb_print_hex(sb, nd_opt_prefix_info->nd_opt_pi_prefix.__in6_u.__u6_addr8, 16);
                break;
            case ND_OPT_MTU:
                nd_opt_mtu = (struct nd_opt_mtu*) (packet + nd_option_offset);
                sb_printf(sb, "/%i/%u", ND_OPT_MTU, ntohl(nd_opt_mtu->nd_opt_mtu_mtu));
                break;
            case ND_OPT_RDNS:
                nd_opt_rdns = (struct nd_opt_rdns*) nd_opt_hdr;
                rdns = (nd_opt_rdns->nd_opt_rdns_len - 1) / 2;
                sb_printf(sb, "/%u/%u/%u", ND_OPT_RDNS, ntohl(nd_opt_rdns->nd_opt_rdns_lifetime), rdns);
                for(int i = 0; i < rdns; ++i) {
                    sb_printf(sb, "/");
                    sb_print_hex(sb, packet + nd_option_offset + 8 + i * 16, 16);
                }
                break;
            default:
                fprintf(stderr, "ignoring unknown option: %i\n", nd_opt_hdr->nd_opt_type);
                break;
            }
            nd_option_offset += nd_opt_hdr->nd_opt_len * 8;
        }
    }

    if (sb->overflow) {
        fprintf(stderr, "not publishing truncated message");
    } else {
        redisPublish(redis_ctx, "ip6:in", sb->buffer);
    }
    sb_free(sb);
}

// note: fields are ordered as stated in RFC4861
void sb_print_router_advert_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct nd_router_advert)) {
        return;
    }

    struct nd_router_advert* nd_router_advert = (struct nd_router_advert*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    sb_printf(sb, "/%u/%u/%u/%u/%i/%u/%u/%u",
              nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[0],
              nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] >> 7,
              nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] >> 6 & 1,
              nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] >> 5 & 1,
              (int8_t)(nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] << 3) >> 6,
              ntohs(nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data16[1]),
              ntohl(nd_router_advert->nd_ra_reachable),
              ntohl(nd_router_advert->nd_ra_retransmit));
}

void sb_print_neighbor_advert_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)) {
        return;
    }

    struct nd_neighbor_advert* nd_neighbor_advert = (struct nd_neighbor_advert*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    sb_printf(sb, "/%u/%u/%u/",
              nd_neighbor_advert->nd_na_hdr.icmp6_dataun.icmp6_un_data8[0] >> 7,
              nd_neighbor_advert->nd_na_hdr.icmp6_dataun.icmp6_un_data8[0] >> 6 & 1,
              nd_neighbor_advert->nd_na_hdr.icmp6_dataun.icmp6_un_data8[0] >> 5 & 1);
    sb_print_hex(sb, nd_neighbor_advert->nd_na_target.__in6_u.__u6_addr8, 16);
}

void sb_print_neighbor_solicit_info(struct sb* sb, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit)) {
        return;
    }

    struct nd_neighbor_solicit* nd_neighbor_solicit = (struct nd_neighbor_solicit*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

    sb_printf(sb, "/");
    sb_print_hex(sb, nd_neighbor_solicit->nd_ns_target.__in6_u.__u6_addr8, 16);
}

int main(int argc,char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: arp_read <interface>\n");
        return 1;
    }
    const char* interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    // Ask pcap for the network address and netmask
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    pcap_lookupnet(interface, &netp, &maskp, errbuf);

    // Open device for capturing in promiscuous mode
    context = pcap_open_live(interface, BUFSIZ, 1, 10, errbuf);
    if (context == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return 1;
    }
    // Build a filter looking for ARP packets only:
    struct bpf_program program;

    // Get own mac addr
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

        char filter[73];
        // capture any arp / dhcp / icmpv6 traffic not originating from us
        sprintf(filter, "not ether src %02x:%02x:%02x:%02x:%02x:%02x and (arp or port bootpc or ip6 proto 58)",
                (unsigned char) s.ifr_addr.sa_data[0],
                (unsigned char) s.ifr_addr.sa_data[1],
                (unsigned char) s.ifr_addr.sa_data[2],
                (unsigned char) s.ifr_addr.sa_data[3],
                (unsigned char) s.ifr_addr.sa_data[4],
                (unsigned char) s.ifr_addr.sa_data[5]);
        if (pcap_compile(context, &program, filter, 0, netp) == -1) {
            fprintf(stderr, "Error calling pcap_compile\n");
            return 1;
        }
    } else {
        return 1;
    }

    if (pcap_setfilter(context, &program) == -1) {
        fprintf(stderr, "Error setting ARP filter\n");
        return 1;
    }

    redisContext* redis_ctx=NULL;
    // Allow retrying when DB connection fails
    while (true) {
        // Connect to Redis DB
        redis_ctx = redisConnect("127.0.0.1", 6379);
        if (redis_ctx == NULL) {
            // connection could not be established
            // wait
            sleep(sleep_duration);

            continue;
        }
        if (redis_ctx != NULL && redis_ctx->err) {
            fprintf(stderr, "redisConnect error: %s\n", redis_ctx->errstr);

            // free all pointers
            redisFree(redis_ctx);redis_ctx=NULL;
            // wait
            sleep(sleep_duration);

            continue;
        }


        // Loop:
        pcap_loop(context, -1, packet_callback, (u_char*)redis_ctx);

        // In case of error, wait and try again
        if (retry) {
            retry = false;
            // free all pointers
            redisFree(redis_ctx);redis_ctx=NULL;

            // wait
            sleep(sleep_duration);

            continue;
        }

        return 0;
    }
}
