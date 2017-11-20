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
 * @brief   Sniffer object file for isamon
 */

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
#include <netinet/tcp.h>
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

// >>> Staticke promenne trid >>>
// Informace o karte
iface_t Sniffer::currNIC;

// Vysledky sniffovani
std::vector<struct in_addr> Sniffer::recordPing;
std::vector<uint32_t> Sniffer::recordUdp;
std::vector<uint32_t> Sniffer::recordTcp;

// Status vlaken
bool Sniffer::arpWorkerReady;
bool Sniffer::icmpWorkerReady;
bool Sniffer::tcpWorkerReady;

// Zamky pro vlakna
bool Sniffer::arpLock;
bool Sniffer::icmpLock;
bool Sniffer::tcpLock;

// Skenujeme UDP porty tehle IP
struct in_addr Sniffer::currInAddrIP;
bool Sniffer::acceptUDP = false;
// <<< Staticke promenne trid <<<

/// sort - Porovna 2 adresy
static bool sortInAddr( const struct in_addr a, const struct in_addr b )
{
	return a.s_addr < b.s_addr;
}

/// unique - Porovna 2 adresy
static bool cmpInAddr( const struct in_addr a, const struct in_addr b )
{
	return a.s_addr == b.s_addr;
}

bool Sniffer::Init( const opt_t opt )
{
	// Alokuj misto pro UDP porty
	Sniffer::recordUdp.reserve(65536);
	// porty jsou nastaveny na FALSE pokud jsou zavreny
	// predpokladam, ze jsou otevreny
	for (int i = 0; i <= 65535; i++) {
		Sniffer::recordUdp[i] = true;
	}
	// Predalokuj misto pro IP zaznamy
	Sniffer::recordPing.reserve(64);

	this->opt = opt;

	this->WorkerArg.rttTmval = opt.val.rttTmval;

	return false;
}

std::vector<struct in_addr> Sniffer::getOnlineHosts( void )
{
	// ~~~ Setrid zaznamy a vyber unikatni

	debug << "Sorting "<< recordPing.size()<<" PING records ...\n";
	// for (unsigned i = 0; i < recordPing.size(); i++) {
	// 	debug << " Bef sort // "<<InAddrToIP4(recordPing[i]) << "\n";
	// }

	std::sort(recordPing.begin(), recordPing.end(), sortInAddr);
	// for (unsigned i = 0; i < recordPing.size(); i++) {
	// 	debug << " Aft sort // "<<InAddrToIP4(recordPing[i]) << "\n";
	// }

	recordPing.erase(std::unique(recordPing.begin(), recordPing.end(), cmpInAddr), recordPing.end());
	// for (unsigned i = 0; i < recordPing.size(); i++) {
	// 	debug << " Aft uniq // "<<InAddrToIP4(recordPing[i]) << "\n";
	// }

	debug << "Sniffer found "<<recordPing.size()<<" Online hosts\n";
	return Sniffer::recordPing;
}

std::vector<uint32_t> Sniffer::getOpenUdpPorts( void )
{
	debug << "Returning list of opened UDP ports ...\n";
	std::vector<uint32_t> result;
	for (uint32_t i = 1; i <= 65535; i++) {
		if (std::find(recordUdp.begin(), recordUdp.end(), i) == recordUdp.end()) {
			result.push_back( i );
		}
	}

	debug << "Found " << result.size() << " opened ports\n";

	return result;
}

std::vector<uint32_t> Sniffer::getOpenTcpPorts( void )
{
	debug << "Sorting "<<recordTcp.size()<<" TCP records ...\n";
	std::sort(recordTcp.begin(), recordTcp.end());
	recordTcp.erase(std::unique(recordTcp.begin(), recordTcp.end()), recordTcp.end());
	debug << "Sniffer found "<<recordTcp.size()<<" open TCP ports\n";

	return Sniffer::recordTcp;
}

bool Sniffer::ArpStart( const iface_t iface )
{
	errno = 0;
	debug << "Starting ARP sniffer ...\n";

	Sniffer::currNIC = iface;

	LockObj::Lock(Sniffer::arpLock);
	Sniffer::arpWorkerReady = false;
	if ( pthread_create( &this->arpWorker, NULL, ArpWorker, (void *)&this->WorkerArg)) {
		terror << "Cannot create sniffer thread\n";
		return true;
	}

	debug << "Is sniffer ready ?\n";
	// Pockej maximalne 4K milisekund, pak ukonci s chybou
	unsigned retries = 4000;
	while( Sniffer::arpWorkerReady == false) {
		if (retries-- == 0) {
			terror << "Sniffer waiting timed out ...\n";
			return true;
		}
		usleep(250);
	}

	return false;
}

bool Sniffer::IcmpEchoStart( const iface_t iface )
{
	Sniffer::acceptUDP = false;
	return this->IcmpStart(iface);
}

bool Sniffer::IcmpUdpStart( const iface_t iface, const struct in_addr inAddr )
{
	Sniffer::currInAddrIP = inAddr;
	Sniffer::acceptUDP = true;

	return this->IcmpStart(iface);
}

bool Sniffer::IcmpStart( const iface_t iface )
{
	errno = 0;

	debug << "Starting ICMP sniffer ...\n";

	Sniffer::currNIC = iface;
	Sniffer::icmpWorkerReady = false;
	LockObj::Lock(Sniffer::icmpLock);
	if ( pthread_create( &this->icmpWorker, NULL, Sniffer::IcmpWorker, (void *)&this->WorkerArg)) {
		terror << "Cannot create sniffer thread\n";
		return true;
	}

	debug << "Is sniffer ready ?\n";
	// Pockej maximalne 4K milisekund, pak ukonci s chybou
	unsigned retries = 4000;
	while( Sniffer::icmpWorkerReady == false) {
		if (retries-- == 0) {
			terror << "Sniffer waiting timed out ...\n";
			return true;
		}
		usleep(250);
	}

	return false;
}

bool Sniffer::TcpStart( const iface_t iface, const struct in_addr inAddr )
{
	errno = 0;

	debug << "Starting TCP sniffer ...\n";

	Sniffer::currInAddrIP = inAddr;

	Sniffer::currNIC = iface;
	Sniffer::tcpWorkerReady = false;
	LockObj::Lock(Sniffer::tcpLock);
	if ( pthread_create( &this->tcpWorker, NULL, Sniffer::TcpWorker, (void *)&this->WorkerArg)) {
		terror << "Cannot create sniffer thread\n";
		return true;
	}

	debug << "Is sniffer ready ?\n";
	// Pockej maximalne 4K milisekund, pak ukonci s chybou
	unsigned retries = 4000;
	while( Sniffer::tcpWorkerReady == false) {
		if (retries-- == 0) {
			terror << "Sniffer waiting timed out ...\n";
			return true;
		}
		usleep(250);
	}

	return false;
}

bool Sniffer::ArpStop( void )
{
	errno = 0;

	// Pokud sniffer stale pracuje, ukonci ho
	usleep(this->opt.val.rtt * 1000);
	if ( arpWorkerReady == true ) {
		debug << "Waiting for ARP sniffer exit ...\n";

		LockObj::Unlock(Sniffer::arpLock);
		pthread_join(this->arpWorker, NULL);
	}

	debug << "Arp sniffer stopped\n";
	return false;
}

bool Sniffer::IcmpStop( void )
{
	errno = 0;

	// Pokud sniffer stale pracuje, ukonci ho
	usleep(this->opt.val.rtt * 1000);
	if ( Sniffer::icmpWorkerReady == true ) {
		debug << "Waiting for ICMP sniffer exit ...\n";

		LockObj::Unlock(Sniffer::icmpLock);
		pthread_join(this->icmpWorker, NULL);
	}

	debug << "Icmp sniffer stopped\n";
	return false;
}

bool Sniffer::TcpStop( void )
{
	errno = 0;

	// Pokud sniffer stale pracuje, ukonci ho
	usleep(this->opt.val.rtt * 1000);
	if ( Sniffer::tcpWorkerReady == true ) {
		debug << "Waiting for TCP sniffer exit ...\n";

		LockObj::Unlock(Sniffer::tcpLock);
		pthread_join(this->tcpWorker, NULL);
	}

	debug << "Icmp sniffer stopped\n";
	return false;
}

//void * Sniffer::ArpWorker( __attribute__((unused)) void * arg )
void * Sniffer::ArpWorker( void * arg )
{
	errno = 0;

	// Nastaveni pro strukturu SO_RCVTIMEO
	struct timeval timeout = ((worker_arg_t *)arg)->rttTmval;

	int sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if ( sock < 0 ) {
		terror << "Cannot open sniffer socket\n";
		return NULL;
	}

	// Chci poslouchat pouze na karte, kterou jsem dostal zadanou
	if (bindSockToIface(&sock, Sniffer::currNIC.name)) {
		terror << "Cannot bind Arp worker to interface\n";
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
		memcpy(&inaddr, pckt.packet.data+28, sizeof(struct in_addr));
		debug << "ARP " << inet_ntoa(inaddr) << " Alive\n";
		//Sniffer::recordArp.push_back(inet_ntoa(inaddr));
		Sniffer::recordPing.push_back(inaddr);
	}

	close(sock);
	debug << "ARP Worker Stopped\n";

	return NULL;
}

//void * Sniffer::IcmpWorker( __attribute__((unused)) void * arg )
void * Sniffer::IcmpWorker( void * arg )
{
	errno = 0;

	// Nastaveni pro strukturu SO_RCVTIMEO
	struct timeval timeout = ((worker_arg_t *)arg)->rttTmval;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sock < 0 ) {
		terror << "Cannot open sniffer socket\n";
		return NULL;
	}

	// Chci poslouchat pouze na karte, kterou jsem dostal zadanou
	if (bindSockToIface(&sock, Sniffer::currNIC.name)) {
		terror << "Cannot bind Arp worker to interface\n";
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
	int data_size;
	struct in_addr inaddr;
	struct icmp_echo_t * icmpEcho;
	struct icmp_unreach_t * icmpUnreach;

	debug << "ICMP Sniffer accept UDP="<<Sniffer::acceptUDP<<"\n";
	Sniffer::icmpWorkerReady = true;
	while ( LockObj::IsActive(Sniffer::icmpLock) ) {
		data_size = recvfrom(sock, (void *)pckt.packet.data, IP_MAXPACKET, 0, NULL, NULL);
		if ( data_size == -1 ) {
			 //debug << strerror(errno)<<"("<<errno<<"): ICMP recvfrom() error, Probably timed out ...\n";
			 errno = 0;
			 continue;
		}
		pckt.packet.len = data_size;

		if (Sniffer::acceptUDP == true && pckt.packet.len >= (int)sizeof(icmp_unreach_t)) {
			// ~~~ UDP ICMP_UNREACH zpravu
			icmpUnreach = (icmp_unreach_t *)pckt.packet.data;
			if ((icmpUnreach->icmpUnreachResponse.type == ICMP_UNREACH) && (icmpUnreach->icmpUnreachResponse.code == ICMP_UNREACH_PORT)) {
				// Tehle stanice jsem se ptal na port
				memcpy(&inaddr, &(icmpUnreach->ipRequest.daddr), sizeof(struct in_addr));
				// Pokud se aktualne dotazovana IP shoduje s adresou v UDP
				// datagramu, vyhodnot port jako zavreny
				if (currInAddrIP.s_addr == inaddr.s_addr) {
					Sniffer::recordUdp.push_back(ntohs(icmpUnreach->udpRequest.dest));
				}
			}
		}
		if (Sniffer::acceptUDP == false && pckt.packet.len >= (int)sizeof(icmp_echo_t)) {
			// ~~~ Pridej stanici do seznamu ONLINE stanic
			icmpEcho = (icmp_echo_t *)pckt.packet.data;
			memcpy(&inaddr, &(icmpEcho->ipResponse.saddr), sizeof(struct in_addr));
			Sniffer::recordPing.push_back(inaddr);
		}
	}

	close(sock);
	debug << "ICMP Worker Stopped\n";
	debug << "ICMP hosts = "<<recordPing.size()<<"\n";
	debug << "ICMP ports = "<<recordUdp.size()<<"\n";

	return NULL;
}

//void * Sniffer::TcpWorker( __attribute__((unused)) void * arg )
void * Sniffer::TcpWorker( void * arg )
{
	errno = 0;

	// Nastaveni pro strukturu SO_RCVTIMEO
	struct timeval timeout = ((worker_arg_t *)arg)->rttTmval;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
		terror << "Cannot open sniffer socket\n";
		return NULL;
    }

	// Chci poslouchat pouze na karte, kterou jsem dostal zadanou
	if (bindSockToIface(&sock, Sniffer::currNIC.name)) {
		terror << "Cannot bind Tcp worker to interface\n";
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
	int data_size;
	struct tcp_answer_t * answer;

	Sniffer::tcpWorkerReady = true;
    while ( Sniffer::tcpLock ) {
        data_size = recvfrom(sock, (void *)pckt.packet.data, IP_MAXPACKET, 0, NULL, NULL);
        if ( data_size < (int)sizeof(tcp_answer_t) || data_size == -1 ) {
			errno = 0;
			continue;
        }
		pckt.packet.len = data_size;
		answer = (tcp_answer_t *)pckt.packet.data;

		// SYN + ACK na to cekame :)
		if ( answer->tcpResponse.syn == 1
			&& answer->tcpResponse.ack == 1
			&& Sniffer::currInAddrIP.s_addr == answer->ipResponse.saddr) {
				debug << "TCP port "<<ntohs(answer->tcpResponse.source)<<" open\n";
				Sniffer::recordTcp.push_back(ntohs(answer->tcpResponse.source));
		}
	}

    close(sock);

	debug << "TCP Worker Stopped\n";
	return NULL;
}

void Sniffer::ClearPingRecords( void )
{
	Sniffer::recordPing.clear();
}

void Sniffer::ClearUdpRecords( void )
{
	Sniffer::recordUdp.clear();
}

void Sniffer::ClearTcpRecords( void )
{
	Sniffer::recordTcp.clear();
}
