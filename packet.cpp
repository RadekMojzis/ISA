/**
 * This file is part of 'isamon'
 *
 * Copyright (c) 2017, Martin Pumr
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of the <organization> nor the
 *        names of its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL MARTIN PUMR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**/
/**
 * @file    : main.cpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Packet object file for isamon
 */

#include "string.h"


#include <cerrno>

#include "sys/types.h"
#include "sys/socket.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>     // ETH_P_ARP = 0x0806
#include <sys/types.h>
#include <sys/socket.h>

#include <netpacket/packet.h>   // struct sockaddr_ll
#include <net/ethernet.h>       // ETHER_ADD_LEN, ETH_P_*
#include <netinet/if_ether.h>   // struct ether_arp
#include <linux/if_ether.h>     // ETH_P_ARP = 0x0806
#include <arpa/inet.h>          // in_addr_t, htons
#include <sys/ioctl.h>          // ioctl()
#include <net/if.h>             // struct ifreq
#include <sys/time.h>

#include "packet.hpp"
#include "global.hpp"

// ------------------------------------------------------------------
// 				>>> Prevzato >>>
// SRC : www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/ping.c
// ------------------------------------------------------------------
/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static int
in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}
// ------------------------------------------------------------------
// 				<<< Prevzato <<<
// ------------------------------------------------------------------

bool Packet::forgeIcmpEcho( void )
{
	errno = 0;

	this->zero();

	struct icmphdr * icmp = (struct icmphdr *)this->packet.data;
	this->packet.len = sizeof(struct icmphdr) + ICMP_DATA;

	// ~~~ ICMP
	memcpy(packet.data + sizeof(struct icmphdr), "ECHO", strlen("ECHO"));
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = htons( 8888 );
	icmp->un.echo.sequence = htons( 0 );
	icmp->checksum = 0;
	icmp->checksum = in_cksum((uint16_t *)this->packet.data, ICMP_HDRLEN + ICMP_DATA);

	return false;
}

bool Packet::forgeArp( const iface_t iface, const ip4_t dstIP )
{
	errno = 0;

	this->zero();
	this->packet.len = sizeof(struct eth_hdr_t) + sizeof(struct arp_hdr_t);

	struct eth_hdr_t * ethhdr = (struct eth_hdr_t *)this->packet.data;
	struct arp_hdr_t * arphdr = (struct arp_hdr_t *)(this->packet.data + sizeof(struct eth_hdr_t));

	// ~~~ ETH vrstva
	// Dst MAC == Broadcast
	memset( ethhdr->dst_mac, 0xff, HW_ADDR_BYTES );
	memcpy( ethhdr->src_mac, &iface.mac, HW_ADDR_BYTES );
	ethhdr->type[0] = ETH_P_ARP / 256;
	ethhdr->type[1] = ETH_P_ARP % 256;

	// ~~~ ARP vrstva
	arphdr->htype  = htons( 1 );        	 	// 1 == Ethernet
	arphdr->ptype  = htons(ETH_P_IP);			// 2048 == 0x0800
	arphdr->hlen   = HW_ADDR_BYTES;				// 6
	arphdr->plen   = IPV4_BYTES;				// 4
	arphdr->opcode = htons( ARPOP_REQUEST );

	memcpy( arphdr->sender_mac, &iface.mac, HW_ADDR_BYTES );


	char ip[20] = { 0 };
	ip4_t senderIP = InAddrToIP4(iface.nicInAddr);
	sprintf(ip, "%d.%d.%d.%d", senderIP.oct[0], senderIP.oct[1], senderIP.oct[2], senderIP.oct[3]);
	//debug << "ARP sender_ip=" << ip << " X " << senderIP << "\n";
	if ( inet_pton(AF_INET, ip, arphdr->sender_ip) != 1 ) {
		terror << "Packet forging\n";
		return true;
	}

	memset( arphdr->target_mac, 0x00, HW_ADDR_BYTES );

	sprintf(ip, "%d.%d.%d.%d", dstIP.oct[0], dstIP.oct[1], dstIP.oct[2], dstIP.oct[3]);
	//debug << "ARP target_ip=" << ip << "\b";
	if ( inet_pton(AF_INET, ip, arphdr->target_ip) != 1 ) {
		terror << "Packet forging " << strerror(errno) << "\n";
		return true;
	}

	return false;
}

static bool forgeIpHdr( struct iphdr * ip, const struct in_addr saddr, const struct in_addr daddr )
{
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	ip->id = htons(8888);
	ip->frag_off = htons(16384);
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = saddr.s_addr;
	ip->daddr = daddr.s_addr;
	ip->check = in_cksum((unsigned short *)ip, ip->tot_len >> 1);

	return false;
}

static bool forgePshHdr( struct pseudo_header * psh, const struct tcphdr * tcp, const struct in_addr saddr, const struct in_addr daddr )
{
	psh->saddr = saddr.s_addr;
	psh->daddr = daddr.s_addr;
	psh->placeholder = 0;
	psh->proto = IPPROTO_TCP;
	psh->tcplen = htons(sizeof(struct tcphdr));

	memcpy(&(psh->tcp), tcp, sizeof(struct tcphdr));

	return false;
}

bool Packet::forgeTcpSyn( const struct in_addr saddr, const struct in_addr daddr, const uint32_t port )
{
	struct iphdr * ip = (struct iphdr *)this->packet.data;
	struct tcphdr * tcp = (struct tcphdr *)(this->packet.data + sizeof(struct iphdr));

	this->packet.len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	// ~~~ IP hlavicka
	forgeIpHdr(ip, saddr, daddr);

	//TCP Header
	tcp->source = htons( 8888 );
	tcp->dest = htons( port );
	tcp->seq = htonl(33333333);
	tcp->ack_seq = 0;
	tcp->doff = sizeof(struct tcphdr) / 4;
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->window = htons(14600);  // maximum allowed window size
	tcp->check = 0;
	tcp->urg_ptr = 0;

	struct pseudo_header psh;

	// Vyplneni pseudo hlavicky (nutne pro spocitani kontrolniho souctu)
	forgePshHdr( &psh, tcp, saddr, daddr );

	tcp->check = in_cksum((unsigned short*)&psh , sizeof(struct pseudo_header));

	return false;
}

bool Packet::forgeTcpRst( const struct in_addr saddr, const struct in_addr daddr, const uint32_t port )
{
	struct iphdr * ip = (struct iphdr *)this->packet.data;
	struct tcphdr * tcp = (struct tcphdr *)(this->packet.data + sizeof(struct iphdr));

	this->packet.len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	// ~~~ IP hlavicka
	forgeIpHdr(ip, saddr, daddr);

	//TCP Header
	tcp->source = htons( 8888 );
	tcp->dest = htons( port );
	tcp->seq = htonl(33333334);
	tcp->ack_seq = 0;
	tcp->doff = sizeof(struct tcphdr) / 4;
	tcp->fin = 0;
	tcp->syn = 0;
	tcp->rst = 1;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->window = htons(14600);  // maximum allowed window size
	tcp->check = 0;
	tcp->urg_ptr = 0;

	struct pseudo_header psh;

	// Vyplneni pseudo hlavicky (nutne pro spocitani kontrolniho souctu)
	forgePshHdr( &psh, tcp, saddr, daddr );

	tcp->check = in_cksum((unsigned short*)&psh , sizeof(struct pseudo_header));

	return false;
}

void Packet::zero( void )
{
	memset(&(this->packet), 0, sizeof(struct packet_t));
}

void Packet::dump( unsigned offset, unsigned maxBytes )
{
	#ifndef DEBUG
	using namespace std;
	cerr << "-------------------------------------------------\n";
	cerr << " off |  2    4    6    8    10   12   14   16\n";
	cerr << "-------------------------------------------------\n";
	for (unsigned i = 0; i < this->packet.len; i++) {
		if (i >= maxBytes) break;
		if (i % 16 == 0) {
			if (i != 0) {
				cerr << "\n";
			}
			fprintf(stderr, "% 4d | ", i+offset);
		}
		else if (i % 2 == 0) cerr << " ";

		fprintf(stderr, "%02x", this->packet.data[i + offset]);
	}
	cerr << "\n-------------------------------------------------\n";
	cerr << " off |    PACKET DUMP - " << this->packet.len << " bytes\n";
	cerr << "-------------------------------------------------\n";
	#endif
}
