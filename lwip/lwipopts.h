#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

#include "minimal/lwipopts.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmacro-redefined"

#define LWIP_DBG_TYPES_ON LWIP_DBG_LEVEL_SERIOUS

#define LWIP_ERRNO_INCLUDE <errno.h>
#define LWIP_ERR_TO_ERRNO 1

#define LWIP_HOOK_IP4_ROUTE(dest) netif_list
#define LWIP_HOOK_IP6_ROUTE(src, dest) netif_list
#define LWIP_HOOK_IP4_NETIF(iphdr) netif_list
#define LWIP_HOOK_IP6_NETIF(ip6hdr) netif_list
#define LWIP_HOOK_TCP_LISTEN_PCB(tcphdr) tcp_listen_pcbs.listen_pcbs

#define LWIP_UDP 0
#define LWIP_ARP 0
#define LWIP_ICMP 0
#define LWIP_HAVE_LOOPIF 0

#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1

// Define the netif struct
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_IPV6_NUM_ADDRESSES 3
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK 0
#define LWIP_NETIF_REMOVE_CALLBACK 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_IPV6_MLD 0
#define LWIP_NUM_NETIF_CLIENT_DATA 0
#define LWIP_IPV6_AUTOCONFIG 1
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_NETIF_HOSTNAME 0
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define MIB2_STATS 0
#define LWIP_NETIF_HWADDRHINT 0
#define LWIP_NETIF_LOOPBACK 0

// Define the tcp_pcb struct
#define LWIP_WND_SCALE 0

#pragma GCC diagnostic pop

#endif /* LWIP_CUSTOM_LWIPOPTS_H */
