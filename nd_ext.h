/*
  Extended definitions for neighbor discovery protocol which are not available in icmp6.h
*/

#ifndef NETWORK_TOOLS_ND_H
#define NETWORK_TOOLS_ND_H

/* Recursive DNS Server Option (rfc8106) */
#define ND_OPT_RDNS 25
/* Route Information Option (rfc4191) */
#define ND_OPT_ROUTE_INFO 24

struct nd_opt_route_info {
    uint8_t nd_opt_rio_type;
    uint8_t nd_opt_rio_len;
    uint8_t nd_opt_rio_prefix_len;
    uint8_t nd_opt_rio_flags_reserved;
    uint32_t nd_opt_rio_lifetime;
    /* followed by 0, 8 or 16 bytes of prefix */
};

struct nd_opt_rdns {
    uint8_t nd_opt_rdns_type;
    uint8_t nd_opt_rdns_len;
    uint32_t nd_opt_rdns_lifetime;
    /* followed by (len - 1) / 2 ip6 addresses */
};

#endif /* nd_ext.h */
