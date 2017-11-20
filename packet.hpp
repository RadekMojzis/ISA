



#ifndef PACKET_HPP_
#define PACKET_HPP_

#include <cstdint>

#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)

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

/// Vytvoreny paket
struct packet_t {
	unsigned len;                  ///< delka paketu
	uint8_t data[IP_MAXPACKET];    ///< data v paketu
};

// >>> class Packet >>>
class Packet {
public:
	// Vytvoreny paket
	packet_t packet;

	// Vytvor icmp echo paket ( icmphdr )
	bool forgeIcmpEcho( void );
	// Vytvor arp paket (ethhdr + arphdr)
	bool forgeArp( const iface_t iface, const ip4_t dstIP );
	// Ziskej prichozi cas paketu
	bool GetTimestamp( const int sock );

	void zero( void );
	void dump( const packet_t * pckt, unsigned offset=0, unsigned maxBytes=1024 );
}; /* class Packet */
// <<< class Packet <<<

#endif /* PACKET_HPP_ */
