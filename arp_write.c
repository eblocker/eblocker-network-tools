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
#include <hiredis/hiredis.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <assert.h>
#include <netinet/in.h>

#include "nd_ext.h"

/**

   This program subscribes to the Redis channel "arp:out" and sends out an ARP packet
   for every message it receives.

   The format of a message is:
   <operation>/<source MAC>/<source IP>/<target MAC>/<target IP>(/<ethernet target MAC>)

   Only operations 1 (ARP request) and 2 (ARP response) are supported.

   MAC addresses are written as six bytes in hex encoding, e.g. "02d2054170a7"
   IP addresses are written in dot notation, e.g. "192.168.0.1"

 */

const int nStrings = 3;
const char* arpRedisChannel = "arp:out";
const char* ip6RedisChannel = "ip6:out";

void parseAndSendPacket(libnet_t *net, char* message)
{
    u_int8_t source_mac[6];
    u_int8_t target_mac[6];
    u_int8_t source_ip[4];
    u_int8_t target_ip[4];
    u_int8_t ether_target_mac[6];
    int operation;

    int nFields = sscanf(message,
                         "%d/%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx/%hhd.%hhd.%hhd.%hhd/%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx/%hhd.%hhd.%hhd.%hhd/%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                         &operation,
                         &source_mac[0], &source_mac[1], &source_mac[2], &source_mac[3], &source_mac[4], &source_mac[5],
                         &source_ip[0], &source_ip[1], &source_ip[2], &source_ip[3],
                         &target_mac[0], &target_mac[1], &target_mac[2], &target_mac[3], &target_mac[4], &target_mac[5],
                         &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3],
                         &ether_target_mac[0], &ether_target_mac[1], &ether_target_mac[2], &ether_target_mac[3], &ether_target_mac[4], &ether_target_mac[5]
                         );

    if (nFields != 21 && nFields != 27) {
        fprintf(stderr, "expected 21 or 27 fields, but got: %d\n", nFields);
        return;
    }

    if (nFields == 21) {
        memcpy(ether_target_mac, target_mac, 6);
    }

    if (operation != ARPOP_REPLY && operation != ARPOP_REQUEST) {
        fprintf(stderr, "Expected operation to be 1 or 2, got: %d\n", operation);
        return;
    }

    // Build ARP header
    if (libnet_autobuild_arp(operation, source_mac, source_ip, target_mac, target_ip, net) == -1) {
        fprintf(stderr, "Error building ARP header: %s\n", libnet_geterror(net));
        return;
    }

    // Build Ethernet header
    if (libnet_autobuild_ethernet(ether_target_mac, ETHERTYPE_ARP, net) == -1) {
        fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(net));
        return;
    }

    // Write packet
    int bytes_written = libnet_write(net);
    if (bytes_written == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(net));
    } else {
        printf("Sent %d bytes\n", bytes_written);
    }

    libnet_clear_packet(net);
}

void parse_hex(char *in, uint8_t *out, size_t len) {
    static uint8_t table[] = { 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
    for(char* i = in; i < in + len * 2;) {
        *out = table[(*i++) & 0x1f] << 4;
        *out |= table[(*i++) & 0x1f];
        ++out;
    }
}

struct message_parser {
    const char* delimiter;
    char* strtok_saveptr;
    char* next_token;
};

void message_parser_init(struct message_parser* parser, const char* delimiter, char* message) {
    parser->delimiter = delimiter;
    parser->strtok_saveptr = NULL;
    parser->next_token = NULL;
    parser->next_token = strtok_r(message, parser->delimiter, &parser->strtok_saveptr);
}

int message_parser_has_next(struct message_parser* parser) {
    if (parser->next_token != NULL) {
        return 1;
    }
    parser->next_token = strtok_r(NULL, parser->delimiter, &parser->strtok_saveptr);
    return parser->next_token != NULL;
}

char* message_parser_next_token(struct message_parser* parser) {
    if (parser->next_token == NULL) {
        message_parser_has_next(parser);
    }
    char* next_token = parser->next_token;
    parser->next_token = NULL;
    return next_token;
}

int message_parser_next(struct message_parser* parser, char** out) {
    char* token = message_parser_next_token(parser);
    if (token == NULL) {
        fprintf(stderr, "missing token\n");
        return -1;
    }
    *out = token;
    return 0;
}

int message_parser_next_int(struct message_parser* parser, int* out) {
    char* token = message_parser_next_token(parser);
    if (token == NULL) {
        fprintf(stderr, "missing token\n");
        return -1;
    }
    *out = atoi(token);
    return 0;
}

int message_parser_next_uint8(struct message_parser* parser, uint8_t* out) {
    int i;
    if (message_parser_next_int(parser, &i)) {
        return -1;
    }
    if (i < 0 || i > UINT8_MAX) {
        fprintf(stderr, "uint8 out-of-range: %i\n", i);
        return -1;
    }
    *out = (uint8_t) i;
    return 0;
}

int message_parser_next_uint16(struct message_parser* parser, uint16_t* out) {
    int i;
    if (message_parser_next_int(parser, &i)) {
        return -1;
    }
    if (i < 0 || i > UINT16_MAX) {
        fprintf(stderr, "uint16 out-of-range: %i\n", i);
        return -1;
    }
    *out = (uint16_t) i;
    return 0;
}

int message_parser_next_bytes(struct message_parser* parser, size_t n, uint8_t* out) {
    char* token = message_parser_next_token(parser);
    if (token == NULL) {
        fprintf(stderr, "missing token\n");
        return -1;
    }
    if (strnlen(token, n * 2) != n * 2) {
        fprintf(stderr, "expected %lu chars: '%s'\n", n * 2, token);
        return -1;
    }

    parse_hex(token, out, n);
    return 0;
}

struct list_node {
    struct list_node* next;
    void* entry;
};

void list_free(struct list_node* node) {
    while(node != 0) {
        struct list_node* current = node;
        node = node->next;
        free(current->entry);
        free(current);
    }
}

struct icmp6_request {
    uint8_t src_mac[6];
    uint8_t src_ip6[16];
    uint8_t dst_mac[6];
    uint8_t dst_ip6[16];
    uint8_t icmp_type;
    void* parameter;
    struct list_node* nd_options;
};

struct icmp6_echo_request_parameter {
    uint16_t identifier;
    uint16_t sequence;
    uint32_t payload_size;
    // followed by actual payload
};

int icmp6_parse_nd_advert(struct icmp6_request* request, struct message_parser* parser);
int icmp6_parse_nd_solicit(struct icmp6_request* request, struct message_parser* parser);
int icmp6_parse_nd_options(struct icmp6_request* request, struct message_parser* parser);
int icmp6_parse_nd_option_prefix_info(struct message_parser* parser, struct nd_opt_prefix_info* prefix_info);
int icmp6_parse_nd_option_rdns(struct message_parser* parser, struct nd_opt_rdns** rdns);
int icmp6_parse_echo_request(struct icmp6_request* request, struct message_parser* parser);

int icmp6_parse_request(char* message, struct icmp6_request* request) {
    struct message_parser parser;
    message_parser_init(&parser, "/", message);

    if (message_parser_next_bytes(&parser, 6, request->src_mac)) {
        return -1;
    }
    if (message_parser_next_bytes(&parser, 16, request->src_ip6)) {
        return  -1;
    }
    if (message_parser_next_bytes(&parser, 6, request->dst_mac)) {
        return -1;
    }
    if (message_parser_next_bytes(&parser, 16, request->dst_ip6)) {
        return -1;
    }

    char* message_type;
    if (message_parser_next(&parser, &message_type)) {
        return -1;
    }
    if (strcmp("icmp6", message_type) != 0) {
        fprintf(stderr, "unexpected message type: '%s'\n", message_type);
        return -1;
    }

    if (message_parser_next_uint8(&parser, &request->icmp_type)) {
        return -1;
    }
    switch (request->icmp_type) {
    case ND_ROUTER_ADVERT:
        return icmp6_parse_nd_advert(request, &parser);
    case ND_NEIGHBOR_SOLICIT:
        return icmp6_parse_nd_solicit(request, &parser);
    case ICMP6_ECHO_REQUEST:
        return icmp6_parse_echo_request(request, &parser);
    default:
        fprintf(stderr, "unsupported icmp type: %u\n", request->icmp_type);
        return -1;
    }
}

int icmp6_parse_nd_advert(struct icmp6_request* request, struct message_parser* parser) {
    struct nd_router_advert* nd_router_advert = malloc(sizeof(struct nd_router_advert));
    request->parameter = nd_router_advert;

    // current hop limit
    if (message_parser_next_uint8(parser, &nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[0])) {
        return -1;
    }

    int managed_address_configuration_flag;
    if (message_parser_next_int(parser, &managed_address_configuration_flag)) {
        return -1;
    }
    nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] = (uint8_t )(managed_address_configuration_flag & 1) << 7;

    int other_configuration_flag;
    if (message_parser_next_int(parser, &other_configuration_flag)) {
        return -1;
    }
    nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] |= (uint8_t )(other_configuration_flag & 1) << 6;

    int home_agent_flag;
    if (message_parser_next_int(parser, &home_agent_flag)) {
        return -1;
    }
    nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] |= (uint8_t )(home_agent_flag & 1) << 5;

    int router_preference;
    if (message_parser_next_int(parser, &router_preference)) {
        return -1;
    }
    nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1] |= (uint8_t )(router_preference & 3) << 3;

    // router lifetime
    if (message_parser_next_uint16(parser, &nd_router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data16[1])) {
        return -1;
    }

    if (message_parser_next_int(parser, (int*) &nd_router_advert->nd_ra_reachable)) {
        return -1;
    }

    if (message_parser_next_int(parser, (int*) &nd_router_advert->nd_ra_retransmit)) {
        return -1;
    }

    return icmp6_parse_nd_options(request, parser);
}

int icmp6_parse_nd_solicit(struct icmp6_request* request, struct message_parser* parser) {
    struct nd_neighbor_solicit* nd_neighbor_solicit = malloc(sizeof(struct nd_neighbor_solicit));
    request->parameter = nd_neighbor_solicit;
    if (message_parser_next_bytes(parser, 16, nd_neighbor_solicit->nd_ns_target.__in6_u.__u6_addr8)) {
        return -1;
    }
    return icmp6_parse_nd_options(request, parser);
}

int icmp6_parse_nd_options(struct icmp6_request* request, struct message_parser* parser) {
    if (!message_parser_has_next(parser)) {
        return 0;
    }

    struct list_node root;
    root.next = NULL;
    struct list_node* tail = &root;

    while(message_parser_has_next(parser)) {
        uint8_t type;
        message_parser_next_uint8(parser, &type);
        struct nd_opt_hdr* nd_opt_hdr = NULL;
        switch (type) {
        case ND_OPT_SOURCE_LINKADDR:
        case ND_OPT_TARGET_LINKADDR:
            nd_opt_hdr = malloc(8);
            nd_opt_hdr->nd_opt_type = type;
            nd_opt_hdr->nd_opt_len = 1;
            if (message_parser_next_bytes(parser, 6, (uint8_t*)nd_opt_hdr + 2)) {
                fprintf(stderr, "invalid nd option %i linkaddr\n", type);
                list_free(root.next);
                free(nd_opt_hdr);
                return -1;
            }
            break;
        case ND_OPT_PREFIX_INFORMATION:
            nd_opt_hdr = malloc(sizeof(struct nd_opt_prefix_info));
            if (icmp6_parse_nd_option_prefix_info(parser, (struct nd_opt_prefix_info*) nd_opt_hdr)) {
                list_free(root.next);
                free(nd_opt_hdr);
                return -1;
            }
            break;
        case ND_OPT_RDNS:
            if (icmp6_parse_nd_option_rdns(parser, (struct nd_opt_rdns**) &nd_opt_hdr)) {
                list_free(root.next);
                free(nd_opt_hdr);
                return -1;
            }
            break;
        case ND_OPT_MTU:
            nd_opt_hdr = malloc(8);
            nd_opt_hdr->nd_opt_type = ND_OPT_MTU;
            nd_opt_hdr->nd_opt_len = 1;
            if (message_parser_next_int(parser, (int*)&((struct nd_opt_mtu*)nd_opt_hdr)->nd_opt_mtu_mtu)) {
                list_free(root.next);
                free(nd_opt_hdr);
                return -1;
            }
            ((struct nd_opt_mtu*)nd_opt_hdr)->nd_opt_mtu_mtu = htonl(((struct nd_opt_mtu*)nd_opt_hdr)->nd_opt_mtu_mtu);
            break;
        default:
            fprintf(stderr, "unknown option: %i\n", type);
            list_free(root.next);
            return -1;
        }

        struct list_node* node = malloc(sizeof(struct list_node));
        node->entry = nd_opt_hdr;
        node->next = NULL;
        tail->next = node;
        tail = node;
    }

    request->nd_options = root.next;
    return 0;
}

int icmp6_parse_nd_option_prefix_info(struct message_parser* parser, struct nd_opt_prefix_info* prefix_info) {
    memset(prefix_info, 0, sizeof(struct nd_opt_prefix_info));
    prefix_info->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
    prefix_info->nd_opt_pi_len = 4;

    if (message_parser_next_uint8(parser, &prefix_info->nd_opt_pi_prefix_len)) {
        return -1;
    }

    int flag;
    if (message_parser_next_int(parser, &flag)) {
        return -1;
    }
    prefix_info->nd_opt_pi_flags_reserved = (uint8_t) (flag & 1) << 7;

    if (message_parser_next_int(parser, &flag)) {
        return -1;
    }
    prefix_info->nd_opt_pi_flags_reserved |= (uint8_t) (flag & 1) << 6;

    int value;
    if (message_parser_next_int(parser, &value)) {
        return -1;
    }
    prefix_info->nd_opt_pi_valid_time = htonl((uint32_t) value);

    if (message_parser_next_int(parser, &value)) {
        return -1;
    }
    prefix_info->nd_opt_pi_preferred_time = htonl((uint32_t) value);

    if (message_parser_next_bytes(parser, 16, prefix_info->nd_opt_pi_prefix.__in6_u.__u6_addr8)) {
        return -1;
    }

    return 0;
}

int icmp6_parse_nd_option_rdns(struct message_parser* parser, struct nd_opt_rdns** rdns) {
    uint32_t lifetime;
    if (message_parser_next_int(parser, (int*) &lifetime)) {
        return -1;
    }

    int n;
    if (message_parser_next_int(parser, &n)) {
        return -1;
    }
    if (n < 0 || n > 127) {
        fprintf(stderr, "number of dns servers too large or too small: %i\n", n);
        return -1;
    }

    size_t size = sizeof(struct nd_opt_rdns) + n * 16;
    *rdns = malloc(size);
    memset(*rdns, 0, size);
    (*rdns)->nd_opt_rdns_type = ND_OPT_RDNS;
    (*rdns)->nd_opt_rdns_lifetime = htonl(lifetime);
    (*rdns)->nd_opt_rdns_len = 1 + n * 2;

    for(int i = 0; i < n; ++i) {
        if (message_parser_next_bytes(parser, 16, (void*)*rdns + 8 + i * 16)) {
            return -1;
        }
    }
    return 0;
}

int icmp6_parse_echo_request(struct icmp6_request* request, struct message_parser* parser) {
    uint16_t identifier;
    if (message_parser_next_uint16(parser, &identifier)) {
        return -1;
    }

    uint16_t sequence;
    if (message_parser_next_uint16(parser, &sequence)) {
        return -1;
    }

    char* payload_hex = NULL;
    size_t payload_size = 0;
    if (message_parser_has_next(parser)) {
        if (message_parser_next(parser, &payload_hex)) {
            return -1;
        }
        payload_size = strlen(payload_hex) / 2;
    }

    struct icmp6_echo_request_parameter* parameter = malloc(sizeof(struct icmp6_echo_request_parameter) + payload_size);
    parameter->identifier = identifier;
    parameter->sequence = sequence;
    parameter->payload_size = (uint32_t) payload_size;
    if (payload_hex != NULL) {
        parse_hex(payload_hex, (uint8_t *) parameter + sizeof(struct icmp6_echo_request_parameter), parameter->payload_size);
    }
    request->parameter = parameter;
    return 0;
}

void icmp6_print_request(const struct icmp6_request* request) {
    printf("request:\n");
    printf("src\n");
    printf("    mac: %02x:%02x:%02x:%02x:%02x:%02x\n", request->src_mac[0], request->src_mac[1], request->src_mac[2], request->src_mac[3], request->src_mac[4], request->src_mac[5]);
    printf("     ip: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           request->src_ip6[0], request->src_ip6[1], request->src_ip6[2], request->src_ip6[3],
           request->src_ip6[4], request->src_ip6[5], request->src_ip6[6], request->src_ip6[7],
           request->src_ip6[8], request->src_ip6[9], request->src_ip6[10], request->src_ip6[11],
           request->src_ip6[12], request->src_ip6[13], request->src_ip6[14], request->src_ip6[15]);
    printf("dst\n");
    printf("    mac: %02x:%02x:%02x:%02x:%02x:%02x\n", request->dst_mac[0], request->dst_mac[1], request->dst_mac[2], request->dst_mac[3], request->dst_mac[4], request->dst_mac[5]);
    printf("     ip: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           request->dst_ip6[0], request->dst_ip6[1], request->dst_ip6[2], request->dst_ip6[3],
           request->dst_ip6[4], request->dst_ip6[5], request->dst_ip6[6], request->dst_ip6[7],
           request->dst_ip6[8], request->dst_ip6[9], request->dst_ip6[10], request->dst_ip6[11],
           request->dst_ip6[12], request->dst_ip6[13], request->dst_ip6[14], request->dst_ip6[15]);
    printf("icmp type: %i\n", request->icmp_type);
}

#define LIBNET_ICMPV6_NDP_RADV_H 16
#define LIBNET_PBLOCK_ICMPV6_NDP_RADV_H 0x44    /* ICMPv6 NDP neighbor advertisement header */
// define non-public method from libnet
libnet_ptag_t libnet_build_icmpv6_common(
                                         uint8_t type, uint8_t code, uint16_t sum,
                                         const void* specific, uint32_t specific_s, uint8_t pblock_type,
                                         uint8_t *payload, uint32_t payload_s,
                                         libnet_t *l, libnet_ptag_t ptag);

void icmp6_send_packet(libnet_t* net, struct icmp6_request* request) {
    // build options header
    uint16_t length = 0;

    struct list_node* option_node = request->nd_options;
    while(option_node != NULL) {
        struct nd_opt_hdr* hdr = option_node->entry;
        if (hdr->nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
            if (libnet_build_icmpv6_ndp_opt(ND_OPT_SOURCE_LINKADDR, (uint8_t*)hdr + 2, 6, net, 0) == -1) {
                fprintf(stderr, "error building nd source link addr option: %s\n", libnet_geterror(net));
                return;
            }
            length += LIBNET_ICMPV6_NDP_OPT_H + 6;
        } else if(hdr->nd_opt_type == ND_OPT_TARGET_LINKADDR) {
            if (libnet_build_icmpv6_ndp_opt(ND_OPT_TARGET_LINKADDR, (uint8_t*) hdr + 2, 6, net, 0) == -1) {
                fprintf(stderr, "error building nd target link addr option: %s\n", libnet_geterror(net));
                return;
            }
            length += LIBNET_ICMPV6_NDP_OPT_H + 6;
        } else if (hdr->nd_opt_type == ND_OPT_MTU) {
            if (libnet_build_icmpv6_ndp_opt(ND_OPT_MTU, (uint8_t*) hdr + 2, 6, net, 0) == -1) {
                fprintf(stderr, "error building nd mtu option: %s\n", libnet_geterror(net));
                return;
            }
            length += LIBNET_ICMPV6_NDP_OPT_H + 6;
        } else if (hdr->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
            if (libnet_build_icmpv6_ndp_opt(ND_OPT_PREFIX_INFORMATION, (uint8_t*) hdr + 2, 30, net, 0) == -1) {
                fprintf(stderr, "error building nd prefix info option: %s\n", libnet_geterror(net));
                return;
            }
            length += LIBNET_ICMPV6_NDP_OPT_H + 30;
        } else if (hdr->nd_opt_type == ND_OPT_RDNS) {
            if (libnet_build_icmpv6_ndp_opt(ND_OPT_RDNS, (uint8_t*) hdr + 2, hdr->nd_opt_len * 8 - 2, net, 0) == -1) {
                fprintf(stderr, "error building nd rdns option: %s\n", libnet_geterror(net));
                return;
            }
            length += LIBNET_ICMPV6_NDP_OPT_H + hdr->nd_opt_len * 8 - 2;
        } else {
            fprintf(stderr, "unsupported option: %u\n", hdr->nd_opt_type);
            return;
        }
        option_node = option_node->next;
    }

    if (request->icmp_type == ND_ROUTER_ADVERT) {
        struct libnet_icmpv6_ndp_radv {
            uint8_t current_hop_limit;
            uint8_t flags;
            uint16_t router_lifetime;
            uint32_t reachable_time;
            uint32_t retransmit_timer;
        };
        struct libnet_icmpv6_ndp_radv libnet_radv;

        struct nd_router_advert *router_advert = (struct nd_router_advert *) request->parameter;
        libnet_radv.current_hop_limit = router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[0];
        libnet_radv.flags = router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data8[1];
        libnet_radv.router_lifetime = htons(router_advert->nd_ra_hdr.icmp6_dataun.icmp6_un_data16[1]);
        libnet_radv.reachable_time = htonl(router_advert->nd_ra_reachable);
        libnet_radv.retransmit_timer = htonl(router_advert->nd_ra_retransmit);
        libnet_build_icmpv6_common(request->icmp_type, 0, 0, &libnet_radv, sizeof(struct libnet_icmpv6_ndp_radv), LIBNET_PBLOCK_ICMPV6_NDP_NADV_H, NULL, 0, net, 0);
        length += LIBNET_ICMPV6_NDP_RADV_H;
    } else if (request->icmp_type == ND_NEIGHBOR_SOLICIT) {
        struct libnet_in6_addr nd_ns_target;
        memcpy(nd_ns_target.__u6_addr.__u6_addr8, ((struct nd_neighbor_solicit*) request->parameter)->nd_ns_target.__in6_u.__u6_addr8, 16);
        if (libnet_build_icmpv6_ndp_nsol(request->icmp_type, 0, 0, nd_ns_target, NULL, 0, net, 0) == -1) {
            fprintf(stderr, "error building icmpv6 ndp nsol packet: %s\n", libnet_geterror(net));
            return;
        }
        length += LIBNET_ICMPV6_NDP_NSOL_H;
    } else if (request->icmp_type == ICMP6_ECHO_REQUEST) {
        struct icmp6_echo_request_parameter* parameter = (struct icmp6_echo_request_parameter*)request->parameter;
        if (libnet_build_icmpv6_echo(ICMP6_ECHO_REQUEST, 0, 0, parameter->identifier, parameter->sequence, request->parameter + sizeof(struct icmp6_echo_request_parameter), parameter->payload_size, net, 0) == -1) {
            fprintf(stderr, "error building imcpv6 echo request: %s\n", libnet_geterror(net));
            return;
        }
        length += LIBNET_ICMPV6_ECHO_H + parameter->payload_size;
    } else {
        fprintf(stderr, "unsupported icmp type: %u\n", request->icmp_type);
        return;
    }

    // build ipv6 header
    struct libnet_in6_addr source;
    memcpy(source.__u6_addr.__u6_addr8, request->src_ip6, 16);
    struct libnet_in6_addr destination;
    memcpy(destination.__u6_addr.__u6_addr8, request->dst_ip6, 16);
    // +8 if using nd_opt_source ??
    if (libnet_build_ipv6(0, 0, length, IPPROTO_ICMPV6, 0xff, source, destination, NULL, 0, net, 0) == -1) {
        fprintf(stderr, "error building ipv6 packet: %s\n", libnet_geterror(net));
        return;
    }

    // build Ethernet header
    if (libnet_autobuild_ethernet(request->dst_mac, ETHERTYPE_IPV6, net) == -1) {
        fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(net));
        return;
    }

    // Write packet
    int bytes_written = libnet_write(net);
    if (bytes_written == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(net));
    } else {
        printf("Sent %d bytes\n", bytes_written);
    }

    libnet_clear_packet(net);
}

void parseAndSendIp6IcmpPacket(libnet_t *net, char* message) {
    struct icmp6_request request;
    request.nd_options = NULL;
    request.parameter = NULL;

    if (icmp6_parse_request(message, &request) == 0) {
        // icmp6_print_request(&request, options);
        icmp6_send_packet(net, &request);
    } else {
        fprintf(stderr, "parsing icmp request failed - no packet will be send\n");
    }

    if (request.parameter != NULL) {
        free(request.parameter);
    }
    if (request.nd_options != NULL) {
        list_free(request.nd_options);
    }
}

void processReply(libnet_t *net, redisReply* reply)
{
    if (reply->type != REDIS_REPLY_ARRAY) {
        fprintf(stderr, "redis error: expected reply of type array\n");
        return;
    }

    if (reply->elements != nStrings) {
        fprintf(stderr, "redis error: expected array with three elements\n");
        return;
    }

    int i;
    for (i = 0; i < nStrings; i++) {
        if (reply->element[i]->type != REDIS_REPLY_STRING) {
            fprintf(stderr, "redis error: expected array of strings.\n");
            return;
        }
    }

    redisReply* type    = reply->element[0];
    redisReply* channel = reply->element[1];
    redisReply* message = reply->element[2];

    if (strcmp(type->str, "message") != 0) {
        fprintf(stderr, "redis error: expected first element to be 'message'.\n");
        return;
    }

    if (strcmp(channel->str, arpRedisChannel) == 0) {
        parseAndSendPacket(net, message->str);
    } else if (strcmp(channel->str, ip6RedisChannel) == 0) {
        parseAndSendIp6IcmpPacket(net, message->str);
    } else {
        fprintf(stderr, "redis error: unexpected channel '%s'.\n", channel->str);
    }
}


int main(int argc,char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: arp_write <interface>\n");
        return 1;
    }
    char* interface = argv[1];

    char errbuf[LIBNET_ERRBUF_SIZE];

    int sleep_duration = 5;

    libnet_t *net = libnet_init(LIBNET_LINK, interface, errbuf);
    if (net == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return 1;
    }

    while(true) {
        // Connect to Redis DB
        redisContext* redis_ctx = redisConnect("127.0.0.1", 6379);
        if (redis_ctx == NULL) {
            // connection could not be established
            // wait
            sleep(sleep_duration);
            continue;
        }

        if (redis_ctx != NULL && redis_ctx->err) {
            fprintf(stderr, "redisConnect error: %s\n", redis_ctx->errstr);
            redisFree(redis_ctx);
            sleep(sleep_duration);
            continue;
        }

        redisReply* reply = (redisReply*)redisCommand(redis_ctx, "subscribe %s %s", arpRedisChannel, ip6RedisChannel);
        // one reply for each channel: "subscribe <channel> <number of subscribed channels>"
        freeReplyObject(reply);
        redisGetReply(redis_ctx, (void**)&reply);
        freeReplyObject(reply);

        while (redisGetReply(redis_ctx, (void**)&reply) == REDIS_OK) {
            processReply(net, reply);
            freeReplyObject(reply);
        }

        redisFree(redis_ctx);
        sleep(sleep_duration);
    }
}
