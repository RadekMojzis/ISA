
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <vector>
#include <iostream>
#include <algorithm>

#include <netinet/if_ether.h>   // struct ether_arp
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO

#include <arpa/inet.h>          // in_addr_t, htons
#include <linux/if_ether.h>     // ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003

#include <sys/ioctl.h>          // ioctl()
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/if.h>             // struct ifreq
#include <net/ethernet.h>       // ETHER_ADD_LEN, ETH_P_*

#include <netpacket/packet.h>   // struct sockaddr_ll

// Lokalni vypnuti DEBUG hlaseni
//#define NDEBUG

// >>> Knihovny projektu >>>
#include "global.hpp"
#include "lock.hpp"
#include "packet.hpp"
#include "sniffer.hpp"
// <<< Knihovny projektu <<<

// Informace o karte
iface_t Sniffer::iface;
// Status vlaken
bool Sniffer::arpWorkerReady;
bool Sniffer::icmpWorkerReady;
// Zamky pro vlakna
bool Sniffer::arpLock;
bool Sniffer::icmpLock;

// Skenujeme tuhle IP na UDP porty
struct in_addr Sniffer::currInAddrIP;

// Vysledky sniffovani
std::vector<std::string> Sniffer::recordArp;
std::vector<std::string> Sniffer::recordIcmp;
std::vector<unsigned> Sniffer::recordUdp;

void Sniffer::Init( const iface_t iface)
{
	this->iface = iface;
	Sniffer::arpWorkerReady = false;
	Sniffer::icmpWorkerReady = false;
	memset(&Sniffer::currInAddrIP, 0, sizeof(struct in_addr));
}

bool Sniffer::Start( void )
{
	errno = 0;

	if (this->ArpStart()) {
		terror << "Failed to start ARP sniffer\n";
		return true;
	}
	if (this->IcmpStart()) {
		terror << "Failed to start ICMP sniffer\n";
		this->ArpStop();
		return true;
	}

	debug << "Is sniffer ready ?\n";
	do {
		usleep(250);
	} while( ! this->Ready() );

	return false;
}

bool Sniffer::Stop( void )
{
	errno = 0;

	this->ArpStop();
	this->IcmpStop();

	return false;
}

bool Sniffer::Ready( void )
{
	return Sniffer::arpWorkerReady && Sniffer::icmpWorkerReady;
}

bool Sniffer::ArpStart( void )
{
	errno = 0;
	debug << "Starting ARP sniffer ...\n";

	LockObj::Lock(Sniffer::arpLock);
	if ( pthread_create( &this->arpWorker, NULL, Sniffer::ArpWorker, NULL)) {
		terror << "Cannot create sniffer thread\n";
		return true;
	}

	return false;
}

bool Sniffer::ArpStop( void )
{
	errno = 0;

	if ( arpWorkerReady == false ) {
		debug << "Waiting for ARP sniffer exit ...\n";

		LockObj::Unlock(Sniffer::arpLock);
		pthread_join(this->arpWorker, NULL);
	}

	return false;
}

void * Sniffer::ArpWorker( __attribute__((unused)) void * arg )
{
	errno = 0;

	struct timeval timeout;		// Nastaveni pro strukturu SO_RCVTIMEO
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;

	int sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if ( sock < 0 ) {
		terror << "Cannot open sniffer socket\n";
		return NULL;
	}

	// Chci poslouchat pouze na kartě, kterou jsem dostal zadanou
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, Sniffer::iface.name, IFNAMSIZ) != 0) {
		terror << "Cannot bind sniffer to interface\n";
		close(sock);
		return NULL;
	}

	// Na paket budu cekat max 1 sekundu, pak se zeptam, jestli se nenam ukoncit
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		terror << "Cannot set SO_RCVTIMEO for sniffer\n";
		close(sock);
		return NULL;
	}

	Packet pckt;
	struct in_addr inaddr;
	int data_size;

	Sniffer::arpWorkerReady = true;
	while ( LockObj::IsActive(Sniffer::arpLock) ) {
		data_size = recvfrom(sock, pckt.packet.data, IP_MAXPACKET, 0, NULL, NULL);
		if ( data_size == -1) {
			 //debug << strerror(errno)<<"("<<errno<<"): ARP recvfrom() error, Probably timed out ...\n";
			 errno = 0;
			 continue;
		}
		if ( data_size < ETH_HDRLEN + ARP_HDRLEN) {
			 // zahazuj kratke a spatne pakety
			 debug << "Not enough data ARP, dropping ...\n";
			 continue;
		}
		pckt.packet.len = data_size;

		// Tohle by melo bezet na separatnim vlakne, nebo vyuzit FIFO
		// pokud by byl prival paketu prislis velky
		//pckt.GetTimestamp(sock);
		//pckt.ProcessArpSender(&record.inAddr);
		memcpy(&inaddr, pckt.packet.data+28, sizeof(struct in_addr));
		debug << "ARP " << inet_ntoa(inaddr) << " Alive\n";
		Sniffer::recordArp.push_back(inet_ntoa(inaddr));
	}

	close(sock);

	return NULL;
}

bool Sniffer::IcmpStart( void )
{
	errno = 0;

	debug << "Starting ICMP sniffer ...\n";

	LockObj::Lock(icmpLock);
	if ( pthread_create( &this->icmpWorker, NULL, Sniffer::IcmpWorker, NULL)) {
		terror << "Cannot create sniffer thread\n";
		return true;
	}

	return false;
}

bool Sniffer::IcmpStop( void )
{
	errno = 0;

	if ( Sniffer::icmpWorkerReady == false ) {
		debug << "Waiting for ICMP sniffer exit ...\n";

		LockObj::Unlock(icmpLock);
		pthread_join(this->icmpWorker, NULL);
	}
	return false;
}

void * Sniffer::IcmpWorker( __attribute__((unused)) void * arg )
{
	errno = 0;

	struct timeval timeout;		// Nastaveni pro strukturu SO_RCVTIMEO
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sock < 0 ) {
		terror << "Cannot open sniffer socket\n";
		return NULL;
	}

	// Chci poslouchat pouze na kartě, kterou jsem dostal zadanou
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, Sniffer::iface.name, IFNAMSIZ) != 0) {
		terror << "Cannot bind sniffer to interface\n";
		close(sock);
		return NULL;
	}

	// Na paket budu cekat max X sekundu, pak se zeptam, jestli se nenam ukoncit
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		terror << "Cannot set SO_RCVTIMEO for sniffer\n";
		close(sock);
		return NULL;
	}

	Packet pckt;
	std::string record;
	int data_size;
	struct in_addr inaddr;
	struct udp_answer_t * answer;
	//char * dataRequest = NULL;

	debug << "Dropping packets smaller than "<<sizeof(udp_answer_t)<<" Bytes\n";
	Sniffer::icmpWorkerReady = true;
	while ( LockObj::IsActive(Sniffer::icmpLock) ) {
		data_size = recvfrom(sock, (void *)pckt.packet.data, IP_MAXPACKET, 0, NULL, NULL);
		if ( data_size == -1) {
			 //debug << strerror(errno)<<"("<<errno<<"): ICMP recvfrom() error, Probably timed out ...\n";
			 errno = 0;
			 continue;
		}

		pckt.packet.len = data_size;
		answer = (udp_answer_t *)pckt.packet.data;
		//dataRequest = (char*)(pckt.packet.data + sizeof(udp_answer_t));

		// pckt.GetTimestamp(sock);
		/*if ( answer->ipResponse.saddr != 0 )*/ {		/// ignoruj 0.0.0.0
			// Od tehle stanice jsem dostal odpoved => online
			memcpy(&inaddr, &(answer->ipResponse.saddr), sizeof(struct in_addr));
			record = inet_ntoa(inaddr);
			Sniffer::recordIcmp.push_back(record);

			if ((answer->icmpUnreachResponse.type == ICMP_UNREACH) && (answer->icmpUnreachResponse.code == ICMP_UNREACH_PORT)) {
				// Tehle stanice jsem se ptal na port
				memcpy(&inaddr, &(answer->ipRequest.daddr), sizeof(struct in_addr));
				// Pokud se aktualne skenovana IP shoduje s adresou v UDP
				// datagramu, pridej port do seznamu
				if (! memcmp(&Sniffer::currInAddrIP, &inaddr, sizeof(struct in_addr))) {
					Sniffer::recordUdp.push_back(ntohs(answer->udpRequest.dest));
				}
				//pckt.dump(&pckt.packet);
			}
		}
		// else {} // jina ICMP zprava, nejspis ECHO
	}

	close(sock);

	return NULL;
}

bool Sniffer::SetIpOfInterest( const ip4_t ip4 )
{
	char tmp[16] = { 0 };
	sprintf(tmp, "%d.%d.%d.%d", ip4.oct[0], ip4.oct[1], ip4.oct[2], ip4.oct[3]);
	if ( ! inet_aton(tmp, &(Sniffer::currInAddrIP)) ) {
		return true;
	}
	this->currIP = ip4;

	return false;
}

bool Sniffer::IsHostOnline( void )
{
	// Ping timeout
	usleep(this->opt.val.wait * 1000);
	TODO FIXME
	errno = 0;

	std::string tmp = inet_ntoa(this->currInAddrIP);

	for (unsigned i = 0; i < Sniffer::recordIcmp.size(); i++) {
		if (Sniffer::recordIcmp[i] == tmp) {
			debug << "Host " << this->currIP << " online (ICMP)\n";
			std::cout << this->currIP << "\n";
			return true;
		}
	}
	for (unsigned i = 0; i < Sniffer::recordArp.size(); i++) {
		if (Sniffer::recordArp[i] == tmp) {
			debug << "Host " << this->currIP << " online (ARP)\n";
			std::cout << this->currIP << "\n";
			return true;
		}
	}

	return false;
}

bool Sniffer::FlushUdp( void )
{
	errno = 0;

	Sniffer::recordUdp.clear();

	return false;
}

bool Sniffer::FlushAll( void )
{
	errno = 0;

	Sniffer::recordArp.clear();
	Sniffer::recordIcmp.clear();
	Sniffer::recordUdp.clear();

	return false;
}


bool Sniffer::printResults( void )
{
	errno = 0;

	debug << "Sorting sniffed records ...\n";
	for (unsigned i = 0; i < Sniffer::recordIcmp.size(); i++) {
		Sniffer::recordArp.push_back(Sniffer::recordIcmp[i]);
	}

	debug << "Sorting " << Sniffer::recordArp.size() << " records ...\n";
	std::sort( Sniffer::recordArp.begin(), Sniffer::recordArp.end() );
	Sniffer::recordArp.erase( std::unique( Sniffer::recordArp.begin(), Sniffer::recordArp.end() ), Sniffer::recordArp.end() );

	debug << "Flushing " << Sniffer::recordArp.size() << " unique records ...\n";
	for (unsigned i = 0; i < Sniffer::recordArp.size(); i++) {
		std::cout << Sniffer::recordArp[i] << "\n";
	}

	return false;
}

bool Sniffer::printUdpResults( void )
{
	errno = 0;

	debug << "Got "<<Sniffer::recordUdp.size()<<" closed ports\n";
	// for (unsigned i = 0; i < Sniffer::recordUdp.size(); i++) {
	// 	debug << Sniffer::recordUdp[i]<<"\n";
	// }

	debug << "Flushing UDP results ...\n";
	for (unsigned i = 1; i <= 65535; i++) {
		bool flag = true;
		for (unsigned j = 0; j < Sniffer::recordUdp.size(); j++) {
			// Seznam zavrenych portu
			if (i == Sniffer::recordUdp[j]) {
				flag = false;
				break;
			}
		}
		if ( flag ) {
			std::cout << this->currIP << " UDP " << i << "\n";
		}
	}

	return false;
}
