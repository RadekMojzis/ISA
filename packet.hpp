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
 * @brief   Packet object header file for isamon
 */


#ifndef PACKET_HPP_
#define PACKET_HPP_

#include <cstdint>

#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "global.hpp"


#define IP4_HDRLEN	20        // Delka IPv4 hlavicky
#define ICMP_HDRLEN	8         // Delka ICMP hlavicky pro echo request, nepocita data
#define ICMP_DATA	8         // X bajtu ICMP dat
#define ETH_HDRLEN  4         // Delka ETH hlavicky
#define ARP_HDRLEN  8         // Delka ARP hlavicky

#define IPV4_BYTES		4		// X bajtu pro uchovani IPv4
#define HW_ADDR_BYTES	6		// X bajtu pro uchovani MAC

/// RAW eth ramec
struct eth_hdr_t {				// eth offset
	uint8_t dst_mac[6];			// A	0 -  5		+6
	uint8_t src_mac[6];			// B	6 - 11		+6
	uint8_t type[2];			// C	12 - 13		+2
};

/// ARP ramec
struct arp_hdr_t {				// eth + arp offset
	uint16_t htype;         	// A	14 - 15		+2
	uint16_t ptype;				// B	16 - 17		+2
	uint8_t hlen;				// C	18 - 18		+1
	uint8_t plen;				// D	19 - 19		+1
	uint16_t opcode;			// E	20 - 21		+2
	uint8_t sender_mac[6];		// F	22 - 27		+6
	uint8_t sender_ip[4];		// H	28 - 31		+4
	uint8_t target_mac[6];		// J	32 - 37		+6
	uint8_t target_ip[4];		// I	38 - 41		+4
};

/// Pseudo hlavicka potrebna pro spocitani kontrolniho souctu
struct pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t placeholder;
    uint8_t proto;
    uint16_t tcplen;
    struct tcphdr tcp;
};

/// Vytvoreny paket
struct packet_t {
	unsigned len;                  ///< delka paketu
	uint8_t data[IP_MAXPACKET];    ///< data v paketu
};

// >>> class Packet >>>
class Packet {
public:
	/// Vytvoreny paket
	packet_t packet;

	/**
	 * Vytvor ICMP ECHO packet (icmphdr)
	 * @return  [description]
	 */
	bool forgeIcmpEcho( void );
	/**
	 * Vytvor ARP paket (ethhdr + arphdr)
	 * @param  iface NIC, pres kterou bude ramec odeslan
	 * @param  dstIP Cilova IP adresa
	 * @return       FALSE pokud vse ok, jinak TRUE
	 */
	bool forgeArp( const iface_t iface, const ip4_t dstIP );
	/**
	 * Vytvori TCP SYN paket (iphdr + tcphdr)
	 * @param  saddr Zdrojova IP adresa NIC
	 * @param  daddr Cilova IP adresa
	 * @param  port  Cilovy port
	 * @return       FALSE pokud vse ok, jinak TRUE
	 */
	bool forgeTcpSyn( const struct in_addr saddr, const struct in_addr daddr, const uint32_t port );
	/**
	 * Vytvori TCP RST paket (iphdr + tcphdr)
	 * @param  saddr Zdrojova IP adresa NIC
	 * @param  daddr Cilova IP adresa
	 * @param  port  Cilovy port
	 * @return       FALSE pokud vse ok, jinak TRUE
	 */
	bool forgeTcpRst( const struct in_addr saddr, const struct in_addr daddr, const uint32_t port );
	/**
	 * Smaz obsah paketu
	 */
	void zero( void );
	/**
	 * Hexdump paketu
	 * @param offset   Od ktereho bajtu se zacne tisknout (implicitne 0)
	 * @param maxBytes Kolik bajtu bude maximalne zobrazeno (implicitne 1024)
	 */
	void dump( unsigned offset=0, unsigned maxBytes=1024 );
}; /* class Packet */
// <<< class Packet <<<

#endif /* PACKET_HPP_ */
