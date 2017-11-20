

#include "string.h"


#include <cerrno>

#include "sys/types.h"
#include "sys/socket.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO
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

// Prevzato z prednasek ISA 2017
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum(uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

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
	icmp->un.echo.id = htons( 1111 );
	icmp->un.echo.sequence = htons( 0 );
	icmp->checksum = 0;
	icmp->checksum = checksum((uint16_t *)this->packet.data, ICMP_HDRLEN + ICMP_DATA);

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

	char ip[20] = { 0 };

	memcpy( arphdr->sender_mac, &iface.mac, HW_ADDR_BYTES );
	sprintf(ip, "%d.%d.%d.%d", iface.ipAddr.oct[0], iface.ipAddr.oct[1], iface.ipAddr.oct[2], iface.ipAddr.oct[3]);
	//debug << "ARP sender_ip=" << ip << std::endl;
	if ( inet_pton(AF_INET, ip, arphdr->sender_ip) != 1 ) {
		terror << "Packet forging\n";
		return true;
	}

	memset( arphdr->target_mac, 0x00, HW_ADDR_BYTES );

	sprintf(ip, "%d.%d.%d.%d", dstIP.oct[0], dstIP.oct[1], dstIP.oct[2], dstIP.oct[3]);
	//debug << "ARP target_ip=" << ip << std::endl;
	if ( inet_pton(AF_INET, ip, arphdr->target_ip) != 1 ) {
		terror << "Packet forging " << strerror(errno) << "\n";
		return true;
	}

	return false;
}

bool Packet::GetTimestamp( const int sock )
{
	errno = 0;

	// Kdy byl paket prijat
	gettimeofday(&this->tmstamp.tv_tod, 0);

	// Kdy byl paket zaznamenan kernelem
	if (ioctl(sock, SIOCGSTAMP, &this->tmstamp.tv_ioctl)) {
		return true;
	}

	return false;
}

void Packet::zero( void )
{
	memset(&(this->packet), 0, sizeof(struct packet_t));
}

void Packet::dump( const packet_t * pckt, unsigned offset, unsigned maxBytes )
{
	#ifndef DEBUG
	using namespace std;
	cerr << "-------------------------------------------------\n";
	cerr << " off |  2    4    6    8    10   12   14   16\n";
	cerr << "-------------------------------------------------\n";
	for (unsigned i = 0; i < pckt->len; i++) {
		if (i >= maxBytes) break;
		if (i % 16 == 0) {
			if (i != 0) {
				cerr << "\n";
			}
			fprintf(stderr, "% 4d | ", i+offset);
		}
		else if (i % 2 == 0) cerr << " ";

		fprintf(stderr, "%02x", pckt->data[i + offset]);
	}
	cerr << "\n-------------------------------------------------\n";
	cerr << " off |    PACKET DUMP - " << pckt->len << " bytes\n";
	cerr << "-------------------------------------------------\n";
	#endif
}
