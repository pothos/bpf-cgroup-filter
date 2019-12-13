/* Copyright 2019 Kai Lüke <kailueke@riseup.net>
 * SPDX-License-Identifier: GPL-2.0
 *
 * Minimal configurable packet filter, parses IP/IPv6 packets, ICMP, UDP ports,
 * and TCP ports. The forward rule is a C expression passed as FILTER variable
 * to the compiler with -D. The expression can use the boolean variables
 * [udp, tcp, icmp, ip, ipv6] and the integers [dst_port, src_port].
 * If the expression evaluates to 0 (false), the packet will be dropped.
 */

 /* Workaround for "/usr/include/gnu/stubs.h:7:11: fatal error: 'gnu/stubs-32.h' file not found" */
#define __x86_64__

#include <linux/bpf.h>
#include "bpf_api.h"
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

/* cgroup/skb BPF prog */
__section("filter")
int port_firewall(struct __sk_buff *skb) {
  __u8 udp = 0, tcp = 0, icmp = 0, ip = 0, ipv6 = 0;
  __u16 dst_port = 0;
  __u16 src_port = 0;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  ip = skb->protocol == htons(ETH_P_IP);
  ipv6 = skb->protocol == htons(ETH_P_IPV6);

  if (ip) {
    if (data + sizeof(struct iphdr) > data_end) { return 0; }
    struct iphdr *ip = data;
    /* IP fragmentation does not need to be handled here for cgroup skbs */
    icmp = ip->protocol == IPPROTO_ICMP;
    tcp = ip->protocol == IPPROTO_TCP;
    udp = ip->protocol == IPPROTO_UDP;
    if (udp || tcp) {
      __u8 *ihlandversion = data;
      __u8 ihlen = (*ihlandversion & 0xf) * 4;
      if (data + ihlen + sizeof(struct tcphdr) > data_end) { return 0; }
      struct tcphdr *tcp = data + ihlen;
      src_port = ntohs(tcp->source);
      dst_port = ntohs(tcp->dest);
    }
  } else if (ipv6) {
    struct ipv6hdr *ipv6 = data;
    __u8 ihlen = sizeof(struct ipv6hdr);
    if (((void *) ipv6) + ihlen > data_end) { return 0; }
    __u8 proto = ipv6->nexthdr;
    #pragma unroll
    for (int i = 0; i < 8; i++) { /* max 8 extension headers */
      icmp = proto == IPPROTO_ICMPV6;
      tcp = proto == IPPROTO_TCP;
      udp = proto == IPPROTO_UDP;
      if (udp || tcp) {
        if (((void *) ipv6) + ihlen + sizeof(struct tcphdr) > data_end) { return 0; }
        struct tcphdr *tcp = ((void *) ipv6) + ihlen;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
      }
      if (icmp || udp || tcp) {
        break;
      }
      if (proto == IPPROTO_FRAGMENT || proto == IPPROTO_HOPOPTS ||
          proto == IPPROTO_ROUTING || proto == IPPROTO_AH || proto == IPPROTO_DSTOPTS) {
        if (((void *) ipv6) + ihlen + 2 > data_end) { return 0; }
        ipv6 = ((void *) ipv6) + ihlen;
        proto = *((__u8 *) ipv6);
        if (proto == IPPROTO_FRAGMENT) {
          ihlen = 8;
        } else {
          ihlen = *(((__u8 *) ipv6) + 1) + 8;
        }
        if (((void *) ipv6) + ihlen > data_end) { return 0; }
      } else {
        break;
      }
    }
  }

  if (FILTER) {
    return 1; /* 1 = forward */
  }
  return 0; /* 0 = drop */
}

char __license[] __section("license") = "GPL";
