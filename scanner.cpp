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
 * @file    : scanner.cpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Scanner object file for isamon
 */

#include <cerrno>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <net/if.h>             // struct ifreq
#include <ifaddrs.h>
#include <sys/ioctl.h>          // ioctl()
#include <sys/types.h>
#include <arpa/inet.h>          // in_addr_t, htons
#include <net/ethernet.h>       // ETHER_ADD_LEN, ETH_P_*
#include <netpacket/packet.h>   // struct sockaddr_ll

//#define NDEBUG

// >>> Knihovny projektu >>>
#include "global.hpp"
#include "packet.hpp"
#include "scanner.hpp"
#include "sniffer.hpp"
// <<< Knihovny projektu <<<

// >>> Lokalni staticke funkce >>>

// <<< Lokalni staticke funkce <<<
// >>> Tridni funkce >>>

bool Scanner::Init( const iface_t iface, const opt_t opt )
{
	errno = 0;

	debug << "Initializing net ...\n";

	this->opt = opt;
	this->currNIC = iface;

	// ~~~ Nastav privatni promenne
	this->netIP4First = this->opt.val.net;
	debug << "NIC first ip "<<InAddrToIP4(iface.nicNetInAddr)<<" X "<<this->opt.val.net<<"\n";
	if (this->opt.val.net != InAddrToIP4(iface.nicNetInAddr)) {
		debug << "Network IP missmatch\n";
	}

	this->netIP4Last = this->netIP4First | ~ this->opt.val.mask;

	debug << "Net first IP : " << this->netIP4First << "\n";
	debug << "Net last IP  : " << this->netIP4Last << " (broadcast)\n";

	return false;
}

bool Scanner::Start( void )
{
	// ~~~ Oskenuj sit na dane NIC
	if (this->scanNet()) {
		terror << "Error while scanning subnet on " << this->currNIC.name << "\n";
	}

	return false;
}

bool Scanner::scanNet( void )
{
	errno = 0;
	debug << "Scaning net attached to " << this->currNIC.name << " ...\n";

	// ~~~ Zjisti ktere stanice jsou online
	if (this->ScannerTaskPing()) {
		terror << "PING (ARP + IMCP) scan failed\n";
		return true;
	}

	// Skenovany rozsah (pripadne upraven dle parametru -p)
	uint32_t portFirst = 1;
	uint32_t portLast = 65535;
	if (this->opt.flg.port) {
		portFirst = this->opt.val.port;
		portLast = this->opt.val.port;
	}

	// ~~~ Oskenuj vsechny online stanice
	for (auto it = begin(this->onlineHosts); it != end(this->onlineHosts); it++) {
		// ~~~ Pokud IP neni ze skenovaneho pasma, preskoc ji a smaz
		ip4_t currIP = InAddrToIP4(*it);
		debug << " online // " << currIP << "\n";
		if (currIP < this->netIP4First || currIP > this->netIP4Last) {
			debug << currIP << " is from different subnet, dropping ...\n";
			continue;
		}

		// Vypis online stanice
		std::cout << currIP << "\n";

		if (this->opt.flg.tcp) {
			if (this->ScannerTaskTcp(*it, portFirst, portLast)) {
				terror << "TCP scan failed\n";
				return true;
			}
			// Vypis otevrene porty
			for (auto it = begin(this->openedPortsTCP); it != end(this->openedPortsTCP); it++) {
				if (this->opt.flg.port) {
					if (*it == this->opt.val.port) {
						std::cout << currIP << " TCP "<< *it << "\n";
						break;
					}
				} else {
					std::cout << currIP << " TCP "<< *it << "\n";
				}
			}
		}

		if (this->opt.flg.udp) {
			if (this->ScannerTaskUdp(*it, portFirst, portLast)) {
				terror << "UDP Scan failed\n";
				return true;
			}
			// Vypis otevrene porty
			for (auto it = begin(this->openedPortsUDP); it != end(this->openedPortsUDP); it++) {
				if (this->opt.flg.port) {
					if (*it == this->opt.val.port) {
						std::cout << currIP << " UDP "<< *it << "\n";
						break;
					}
				} else {
					std::cout << currIP << " UDP "<< *it << "\n";
				}
			}
		}
	}

	return false;
}

//bool Scanner::IsIpLocal(  __attribute__((unused)) const ip4_t ip )
bool Scanner::IsIpLocal(  __attribute__((unused)) const ip4_t ip )
{
	// TODO FIXME
	return true;
}

bool Scanner::ScannerTaskPing( void )
{
	debug << "Starting PING (ARP + ICMP) Task ...\n";

	Packet pckt;		// Odesilany paket
	Sniffer sniffer;	// Sniffer (chyta ARP, ICMP odpovedi)
	int sockARP;
	struct sockaddr_ll sockLLDesc;	// Linkova vrstva (pouze pro ARP)
	int sockICMP;
	struct sockaddr_in addr;		// Sitova vrstva (ICMP)

	ip4_t currIP;		// Pro skenovaci smycku
	int i = this->netIP4First.oct[0];
	int j = this->netIP4First.oct[1];
	int k = this->netIP4First.oct[2];
	int l = this->netIP4First.oct[3];

	sniffer.Init(this->opt);

	/// ~~~ Inicializuj Arp
	sockARP = this->ScannerTaskArpInit(&sockLLDesc);
	if (sockARP == -1) {
		terror << "Cannot initialize ARP task\n";
		goto ERR_ARP_SOCK;
	}
	if (sniffer.ArpStart(this->currNIC)) {
		terror << "Cannot start ARP sniffer\n";
		goto ERR_ARP_SNIFFER;
		return true;
	}

	/// ~~~ Inicializuj Icmp
	addr.sin_family = AF_INET;
	addr.sin_port = htons(7);

	sockICMP = this->ScannerTaskIcmpInit();
	if (sockICMP == -1 ) {
		terror << "Cannot initialize ICMP task\n";
		goto ERR_ICMP_SOCK;
	}
	if (sniffer.IcmpEchoStart(this->currNIC)) {
		terror << "Cannot start ICMP sniffer\n";
		goto ERR_ICMP_SNIFFER;
	}

	/// ~~~ Zacni skenovat

	std::cout << "Starting scan ["<<this->netIP4First<<"-"<<this->netIP4Last<<"] ...\n";
	for ( ; i < 256; i++) {
		for ( ; j < 256; j++) {
			for ( ; k < 256; k++) {
				for ( ; l < 256; l++) {
					currIP = { (uint8_t)i, (uint8_t)j, (uint8_t)k, (uint8_t)l};
					debug << " // " << currIP << "\n";

					// ~~~ ARP : Priprava, odeslani a nulovani paketu
					// pouze pokud je IP lokalni
					if (this->IsIpLocal(currIP)) {
						pckt.forgeArp( this->currNIC, currIP );
						if (sendto(sockARP, pckt.packet.data, pckt.packet.len, 0, (struct sockaddr *)&sockLLDesc, sizeof(struct sockaddr_ll)) <= 0) {
							terror << "ARP : Cannot send forged packet\n";
						}
						pckt.zero();
					}

					// ~~~ ICMP : Priprava, odeslani a nulovani paketu
					addr.sin_addr = IP4ToInAddr(currIP);

					pckt.forgeIcmpEcho();
					// NE, USLEEP TU SPATNE RESENI
					// TO JE JEDINE RESENI JAK DOCILIT TOHO ABY TO FUNGOVALO I
					// PRAKTICKY A NE JEN TEORETICKY ...
					usleep(15);
					// NEBLOKUJICI ODESILANI ZAHLTI VYSTUPNI BUFFER. POKUD JE
					// SKENOVANYCH STANIC MOC, KERNEL NESTIHA POCITAT CKSUM A
					// DOPLNOVAT IP HLAVICKY, DUSLEDKEM JE
					// CHYBA 105 - NO BUFFER SPACE AVALIABLE
					if (sendto(sockICMP, pckt.packet.data, pckt.packet.len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) <= 0) {
					 	terror << "ICMP : Cannot send forged packet\n";
					}
					pckt.zero();

					// Ukonci sken pokud IP byla posledni
					if ( this->netIP4Last == currIP ) {
						close(sockARP);
						close(sockICMP);
						sniffer.ArpStop();
						sniffer.IcmpStop();
						this->onlineHosts = sniffer.getOnlineHosts();
						sniffer.ClearPingRecords();
						debug << "Ping scan done ... :)\n";
						return false;
					}
				}
				l = 0;
			}
			k = 0;
		}
		j = 0;
	}

	// Tady ziji Stribrni Draci, sem by se program nikdy nemel dostat
	return false;

	ERR_ICMP_SNIFFER:
	close(sockICMP);
	ERR_ICMP_SOCK:
	sniffer.ArpStop();
	ERR_ARP_SNIFFER:
	close(sockARP);
	ERR_ARP_SOCK:

	return true;
}

// ------------------------------------------------------------------
// >>> Arp >>>
// ------------------------------------------------------------------

int Scanner::ScannerTaskArpInit( struct sockaddr_ll * sockLLDesc )
{
	debug << "Initializing ARP Task ...\n";
	// ~~~ Otevreni soketu
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if ( sock < 0 ) {
		terror << "Sock ARP\n";
		return -1;
	}

	// ~~~ Nastaveni soketu
	if (bindSockToIface(&sock, this->currNIC.name)) {
		terror << "Cannot bind ARP socket to NIC\n";
		close(sock);
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	memset(sockLLDesc, 0, sizeof(struct sockaddr_ll));

	debug << "Setting IFREQ stats for device "<<this->currNIC.name<<" ...\n";
	snprintf( ifr.ifr_name, sizeof(ifr.ifr_name), "%s", this->currNIC.name );
	if ( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 ) {
		terror << "Cannot set IFR\n";
		close(sock);
		return -1;
	}

	memcpy(sockLLDesc->sll_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_BYTES);

	// Nastaveni linkove vrstvy soketu
	debug << "Setting Link layer interface to " << this->currNIC.name << "\n";
	if ((sockLLDesc->sll_ifindex = if_nametoindex(this->currNIC.name)) == 0) {
		terror << "\n";
		close(sock);
		return -1;
	}

	sockLLDesc->sll_family = AF_PACKET;
	sockLLDesc->sll_halen = HW_ADDR_BYTES;
	sockLLDesc->sll_protocol = htons(ETH_P_ARP);
	sockLLDesc->sll_hatype = htons(ARPHRD_ETHER);
	sockLLDesc->sll_pkttype = (PACKET_BROADCAST);

	return sock;
}

// ------------------------------------------------------------------
// <<< Arp <<<
// ------------------------------------------------------------------
// >>> Icmp >>>
// ------------------------------------------------------------------

int Scanner::ScannerTaskIcmpInit( void )
{
	debug << "Initializing ICMP Task ...\n";

	// ~~~ Otevreni soketu
	int sockICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sockICMP < 0 ) {
		terror << "Sock ICMP\n";
		return -1;
	}

	// ~~~ Nastaveni soketu
	// Broadcast
	int broadcastPermission = 1;
	if (setsockopt(sockICMP, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastPermission, sizeof(broadcastPermission)) < 0) {
		terror << "ICMP Broadcast ping not allowed\n";
		this->icmpBroadcastEnable = false;
	} else {
		this->icmpBroadcastEnable = true;
	}
	// Pripojeni soketu ke karte
	if (bindSockToIface(&sockICMP, this->currNIC.name)) {
		terror << "Cannot bind ICMP socket to NIC "<<this->currNIC.name<<"\n";
		close(sockICMP);
		return -1;
	}

	return sockICMP;
}

// ------------------------------------------------------------------
// <<< Icmp <<<
// ------------------------------------------------------------------
// >>> Tcp >>>
// ------------------------------------------------------------------

int Scanner::ScannerTaskTcpInit( void )
{
	debug << "Initializing TCP Task ...\n";
	int sockTCP = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockTCP < 0) {
		terror << "Cannot open TCP socket\n";
		return -1;
	}

	if (bindSockToIface(&sockTCP, this->currNIC.name)) {
		terror << "Cannot bind TCP socket to NIC "<<this->currNIC.name<<"\n";
		close(sockTCP);
		return -1;
	}

	// Zprava pro kernel, ze paket obsahuje hlavicky
	int one = 1;
	const int *val = &one;
	if (setsockopt(sockTCP, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		terror << "Cannot set IP_HDRINCL\n";
		close(sockTCP);
		return -1;
	}

	return sockTCP;
}

static bool sendTcpPacket( const int sockTCP, const uint8_t * packet, const unsigned long len, const struct in_addr dstInAddr )
{
	struct sockaddr_in addr;

	addr.sin_addr = dstInAddr;
	addr.sin_family = AF_INET;

	if ( sendto(sockTCP, packet, len, 0 , (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		return true;
	}

	return false;
}

bool Scanner::ScannerTaskTcp( const struct in_addr dstInAddr, const uint32_t portFirst, const uint32_t portLast )
{
	debug << "Starting TCP Port task ["<<portFirst<<"-"<<portLast<<"] ...\n";

	// ~~~ Inicializace
	int sockTCP = this->ScannerTaskTcpInit();
	if (sockTCP == -1) {
		terror << "Cannot initialize TCP Task\n";
	}

	Sniffer sniffer;	// Zachytava TCP odpovedi
	Packet pckt;		// Odesilany paket

	sniffer.Init(this->opt);
	if (sniffer.TcpStart(this->currNIC, dstInAddr)) {
		close(sockTCP);
		terror << "Cannot start TCP sniffer\n";
		return true;
	}

	#define PORT_BATCH	42

	// // Spusti davkove skenovani
	// for (unsigned i = portFirst; i <= portLast; i += PORT_BATCH +1) {
	// 	debug << "// " << InAddrToIP4(dstInAddr) << " TCP " << i << "\r";
	// 	for (unsigned j = i; j < i+PORT_BATCH || j < portLast; j++) {
	// 		pckt.forgeTcpSyn(this->currNIC.nicInAddr, dstInAddr, i);
	// 		if (sendTcpPacket(sockTCP, pckt.packet.data, pckt.packet.len, dstInAddr)) {
	// 			terror << "TCP SYN : Cannot send forged packet\n";
	// 		}
	// 	}
	// 	usleep(this->opt.val.rtt * 1000);
	// 	for (unsigned j = i; j < i+PORT_BATCH || j < portLast; j++) {
	// 		pckt.forgeTcpRst(this->currNIC.nicInAddr, dstInAddr, i);
	// 		if (sendTcpPacket(sockTCP, pckt.packet.data, pckt.packet.len, dstInAddr)) {
	// 			terror << "TCP RST : Cannot send forged packet\n";
	// 		}
	// 	}
	// 	usleep(250);
	// }
    //
	// // ~~~ Skenovani
	debug << "Trying TCP port/s ["<<portFirst<<"-"<<portLast<<"]\n";
	for (unsigned i = portFirst; i <= portLast; i++ ) {
		debug << "// " << InAddrToIP4(dstInAddr) << " TCP " << i << "\r";
		// Jedine co se v paketu meni, je port
		pckt.forgeTcpSyn(this->currNIC.nicInAddr, dstInAddr, i);

		// posli SYN
		if (sendTcpPacket(sockTCP, pckt.packet.data, pckt.packet.len, dstInAddr)) {
			terror << "TCP SYN : Cannot send forged packet\n";
		}

		// posli RST
		pckt.forgeTcpRst(this->currNIC.nicInAddr, dstInAddr, i);
		// usleep(50);
		if (sendTcpPacket(sockTCP, pckt.packet.data, pckt.packet.len, dstInAddr)) {
			terror << "TCP RST : Cannot send forged packet\n";
		}
	}

	close(sockTCP);
	sniffer.TcpStop();
	this->openedPortsTCP = sniffer.getOpenTcpPorts();
	sniffer.ClearTcpRecords();

	return false;
}

// ------------------------------------------------------------------
// <<< Tcp <<<
// ------------------------------------------------------------------
// >>> Udp >>>
// ------------------------------------------------------------------

int Scanner::ScannerTaskUdpInit( void )
{
	debug << "Initializing UDP Task ...\n";
	// ~~~ Otevreni soketu
	int sockUDP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sockUDP < 0 ) {
		terror << "Sock UDP\n";
		return -1;
	}

	// ~~~ Nastaveni soketu
	int broadcastPermission = 1;
	if (setsockopt(sockUDP, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastPermission, sizeof(broadcastPermission)) < 0) {
		terror << "UDP Broadcast not allowed\n";
		this->udpBroadcastEnable = true;
	} else {
		this->udpBroadcastEnable = false;
	}

	return sockUDP;
}

bool Scanner::ScannerTaskUdp( const struct in_addr dstInAddr, const uint32_t portFirst, const uint32_t portLast )
{
	debug << "Starting UDP Port task ["<<portFirst<<"-"<<portLast<<"] ...\n";

	// ~~~ Inicializace
	int sockUDP = this->ScannerTaskUdpInit();
	if (sockUDP == -1) {
		terror << "Cannot initialize UDP Task\n";
		return true;
	}

	Sniffer sniffer;
	sniffer.Init(this->opt);
	if (sniffer.IcmpUdpStart(this->currNIC, dstInAddr)) {
		terror << "Cannot start UDP sniffer ...\n";
		close(sockUDP);
		return true;
	}

	// ~~~ Skenovani
	char buffer[16] = { 0 };
	struct sockaddr_in addr;

	addr.sin_addr = dstInAddr;
	addr.sin_family = AF_INET;

	debug << "Trying UDP port/s ["<<portFirst<<"-"<<portLast<<"]\n";
	for (unsigned i = portFirst; i <= portLast; i++ ) {
		if ( i % 5 == 0) debug << "// " << InAddrToIP4(dstInAddr) << " UDP " << i << "\r";
		addr.sin_port = htons( i );

		// Pro kontrolu pridej do do payloadu cislo skenovaneho portu
		sprintf(buffer, "%u", i);
		if (sendto(sockUDP, buffer, 8, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			terror << "Cannot send UDP request to port " << i << "\n";
			//return true;
		}

		// Prevence DOS
		usleep(1000);
	}

	sniffer.IcmpStop();
	this->openedPortsUDP = sniffer.getOpenUdpPorts();
	sniffer.ClearUdpRecords();

	close(sockUDP);

	return false;
}

// ------------------------------------------------------------------
// <<< Udp <<<
// ------------------------------------------------------------------

// <<< Tridni funkce <<<
