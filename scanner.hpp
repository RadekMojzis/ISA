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
 * @file    : scanner.hpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Scanner object header file for isamon
 */



#ifndef SCANNER_HPP_
#define SCANNER_HPP_

#include <vector>

#include <net/if.h>             // struct ifreq
#include <netpacket/packet.h>   // struct sockaddr_ll

#include "global.hpp"

class Scanner {

public:

	/**
 	 * Inicializuje skener pro skenovani na zadane NIC
 	 * @param  iface Skenovani bude probihat na tomto rozhrani
	 * @param  opt   Nastaveni skeneru (argumenty)
 	 * @return	FALSE pokud vse ok, jinak TRUE
	 */
	bool Init( const iface_t iface, const opt_t opt );

	/**
	 * Spust skenner a postupne oskenuj vsechny subnety
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool Start( void );

private:
	/// Nastaveni skeneru (argumenty)
	opt_t opt;
	/// NIC na ktere aktualne probiha sken
	iface_t currNIC;
	/// Prvni a posledni skenovana IP
	ip4_t netIP4First;
	ip4_t netIP4Last;

	/// Seznam aktivních stanic, které odpovedeli
	/// na ICMP ECHO dle RFC 1122, nebo na ARP dotaz z dane NIC
	std::vector<struct in_addr> onlineHosts;

	/// Seznam otevrenych UDP portu
	std::vector<uint32_t> openedPortsUDP;
	std::vector<uint32_t> openedPortsTCP;

	/**
	 * Oskenuj jeden subnet
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool scanNet( void );

	/**
	 * Je aktualne skenovana IP adresa lokalni adresou?
	 * pokud ano, pouzij navic ARP dotaz
	 * @param  ip Dotazovana IP
	 * @return    TRUE pokud je lokalni, jinak FALSE
	 */
	bool IsIpLocal( const ip4_t ip );

	/**
	 * Zjistuje dostupnost stanic pomoci ICMP + ARP
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool ScannerTaskPing( void );

// ------------------------------------------------------------------
// 			Cast tridy popisujici skenovani ARP
// ------------------------------------------------------------------
private:
	/**
	 * Inicializuj Arp scanner
	 * @param  sockLLDesc Popis soketu na urovni linkove vrstvy
	 * @return            sockfd pokud vse ok, jinak -1
	 */
	int ScannerTaskArpInit( struct sockaddr_ll * sockLLDesc );

// ------------------------------------------------------------------
// 			Cast tridy popisujici skenovani ICMP
// ------------------------------------------------------------------
private:
	/**
	 * Inicializuje Icmp skener
	 * @return  sockfd pokud vse ok, jinak -1
	 */
	int ScannerTaskIcmpInit( void );
	/// Je povoleno pingovat broadcast ? (implicitne false == NE)
	/// Pokud je zabezpeceni stanic mizerne, lze takto skenovat sit
	bool icmpBroadcastEnable = false;
// ------------------------------------------------------------------
// 			Cast tridy popisujici skenovani TCP
// ------------------------------------------------------------------
private:
	/**
	 * Inicializuj TCP skener
	 * @return  sockfd pokud vse ok, jinak -1;
	 */
	int ScannerTaskTcpInit( void );
	/**
	 * Oskenuje TCP porty v zadanem rozsahu (implicitne 1~65535)
	 * @param  dstInAddr Cilova ip adresa
	 * @param  portFirst Timto portem se zacne
	 * @param  portLast  Timto portem se bude koncit
	 * @return           FALSE pokud vse ok, jinak TRUE
	 */
	bool ScannerTaskTcp( const struct in_addr dstInAddr, const uint32_t portFirst=1, const uint32_t portLast=65535 );
// ------------------------------------------------------------------
// 			Cast tridy popisujici skenovani UDP
// ------------------------------------------------------------------
private:
	/**
	* Inicializuj UDP skener
	* @return  sockfd pokud vse ok, jinak -1;
	*/
	int ScannerTaskUdpInit( void );
	/**
	 * Oskenuje UDP porty v zadanem rozsahu (implicitne 1~65535)
	 * @param  dstInAddr Cilova ip adresa
	 * @param  portFirst Timto portem se zacne
	 * @param  portLast  Timto portem se bude koncit
	 * @return           FALSE pokud vse ok, jinak TRUE
	 */
	bool ScannerTaskUdp( const struct in_addr dstInAddr, const uint32_t portFirst=1, const uint32_t portLast=65535 );

	/// Je povoleno zasilat UDP datagramy na broadcast? (implicitne false == NE)
	bool udpBroadcastEnable = false;
};	/* Class Scanner */

#endif	/* SCANNER_HPP_ */
