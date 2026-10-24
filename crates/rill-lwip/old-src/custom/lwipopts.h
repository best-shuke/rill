/**
 * @file lwipopts.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>
 *
 * @section LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

// enable tun2socks logic
#define TUN2SOCKS 1

#define NO_SYS 1
#define LWIP_TIMERS 1

#define IP_DEFAULT_TTL 64
#define LWIP_ARP 0
#define ARP_QUEUEING 0
#define IP_FORWARD 0
#define LWIP_ICMP 1
#define LWIP_RAW 1
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_SNMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_UDP 1
#define LWIP_UDPLITE 0
#define LWIP_TCP 1
#define LWIP_CALLBACK_API 1
#define LWIP_NETIF_API 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 1
#define LWIP_HAVE_SLIPIF 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define PPP_SUPPORT 0
#define LWIP_IPV6 1
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 1

#if defined __APPLE__
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#define LWIP_TCP_KEEPALIVE 1
#define MEMP_NUM_TCP_PCB 256
#else
#define MEMP_NUM_TCP_PCB 1024
#endif
#elif defined __linux__
#include <endian.h>

// BYTE_ORDER by default is LITTLE_ENDIAN if undefined,
// detects only big endian here.
#if defined __BYTE_ORDER && defined __BIG_ENDIAN
#if _BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif

#define MEMP_NUM_TCP_PCB 1024
#else
#define MEMP_NUM_TCP_PCB 1024
#endif

// disable checksum checks
#define CHECKSUM_CHECK_IP 0
#define CHECKSUM_CHECK_UDP 0
#define CHECKSUM_CHECK_TCP 0
#define CHECKSUM_CHECK_ICMP 0
#define CHECKSUM_CHECK_ICMP6 0

#define LWIP_CHECKSUM_ON_COPY 1
#define LWIP_CHKSUM_ALGORITHM 3

#if defined __APPLE__ && TARGET_OS_IPHONE
// iOS Network Extensions run under a hard memory cap: keep the original
// 1500-MTU sizing there.
#define TCP_MSS 1460
#define TCP_WND (32 * TCP_MSS)
#define TCP_SND_BUF (16 * TCP_MSS)
#else
// TCP_MSS is only the upper bound. With TCP_CALCULATE_EFF_SEND_MSS (on by
// default) lwIP both advertises and sends min(TCP_MSS, netif MTU - 40/60),
// and the TUN listener sets the netif MTU from `tun.mtu`: a 1500 MTU still
// runs 1460-byte segments, 9000 runs 8960.
#define TCP_MSS 8960
// Jumbo segments need a window past the 64 KiB a u16 can advertise.
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 3
// Every connection's window can be in flight at once, queued in packets
// between the kernel and the core: 128 KiB is ~15 segments at MTU 9000 and
// ~90 at 1500. 256 KiB gained a little single-flow throughput but 32 bulk
// flows then overran the queues and collapsed into loss recovery; 64 KiB
// cost a third of MTU-9000 single-flow throughput
// (docs/benchmarks/tun-inbound-2026-10.md).
#define TCP_WND (128 * 1024)
#define TCP_SND_BUF (128 * 1024)
// lwIP derives these from TCP_MSS, which is now the jumbo bound rather
// than the common case — size them for 1460-byte segments instead. The
// default queue length would otherwise cap a 1500-MTU connection far below
// TCP_SND_BUF, and the default low-water mark (TCP_SND_BUF / 2) trips
// init.c's u16 overflow check; the raw API never reads it.
#define TCP_SND_QUEUELEN ((4 * TCP_SND_BUF + 1459) / 1460)
#define TCP_SNDLOWAT (2 * TCP_MSS + 1)
// Only ingress frames come from PBUF_POOL (rust/core.rs `input`), each held
// just until its data is copied out; a jumbo frame takes a chain of
// elements. memp_init touches every element, so keep the 1460-MSS size
// rather than letting it grow with TCP_MSS.
#define PBUF_POOL_BUFSIZE LWIP_MEM_ALIGN_SIZE(1460 + 40 + PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN)
#endif

#if defined __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define MEM_SIZE (512 * 1024)
#else
#define MEM_SIZE (2 * 1024 * 1024)
#endif
#else
#define MEM_SIZE (2 * 1024 * 1024)
#endif

#define MEMP_NUM_TCP_SEG 4096
#define PBUF_POOL_SIZE 512

// #define TCP_MSS 1460
// #define TCP_WND (16 * TCP_MSS)
// #define TCP_SND_BUF (8 * TCP_MSS)
// #define MEM_LIBC_MALLOC 1
// #define MEMP_MEM_MALLOC 1

#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

// needed on 64-bit systems, enable it always so that the same configuration
// is used regardless of the platform
#define IPV6_FRAG_COPYHEADER 1

#define LWIP_DEBUG 0
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define PBUF_DEBUG LWIP_DBG_OFF
#define INET_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP_REASS_DEBUG LWIP_DBG_OFF
#define RAW_DEBUG LWIP_DBG_OFF
#define MEM_DEBUG LWIP_DBG_OFF
#define MEMP_DEBUG LWIP_DBG_OFF
#define SYS_DEBUG LWIP_DBG_OFF
#define TIMERS_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_INPUT_DEBUG LWIP_DBG_OFF
#define TCP_RTO_DEBUG LWIP_DBG_OFF
#define TCP_CWND_DEBUG LWIP_DBG_OFF
#define TCP_WND_DEBUG LWIP_DBG_OFF
#define TCP_RST_DEBUG LWIP_DBG_ON
#define TCP_QLEN_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
#define UDP_DEBUG LWIP_DBG_OFF
#define TCPIP_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF

#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0
#define LWIP_PERF 0

#endif
