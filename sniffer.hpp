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
 * @file    : sniffer.hpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Sniffer object header file for isamon
 */

#ifndef SNIFFER_HPP_
#define SNIFFER_HPP_

#include <pthread.h>

#include <vector>
#include <sys/time.h>
#include <netinet/if_ether.h>   // struct ether_arp
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO

#include <sys/time.h>
#include "global.hpp"
#include "lock.hpp"
#include "packet.hpp"

/// Odpoved, ktera prisla jako vysledek TCP zadosti na port
struct tcp_answer_t {
    /// ip hlavicka odpovedi
    struct iphdr ipResponse;
    /// tcp hlavicka odpovedi
    struct tcphdr tcpResponse;
};

/// Odpoved, ktera prisla jako vysledek ICMP ECHO
struct icmp_echo_t {
    struct iphdr ipResponse;
    struct icmphdr icmpEchoReplay;
};

/// Odpoved, ktera prisla jako vysledek UDP zadosti na port
struct icmp_unreach_t {
    /// +20B
    /// Hlavicku stvoril CIL
 	struct iphdr ipResponse;
    /// + 8B = type + code + cksum + unused + mtu
    /// Tohle stvoril nekdo po ceste
    struct icmphdr icmpUnreachResponse;
    /// +20B
    /// Tohle stvorila moje sitova karta
 	struct iphdr ipRequest;
    /// + 8B
    /// Tohle jsem stvoril ja a jako kopie se mi to vratilo
 	struct udphdr udpRequest;
    // + Alespon 8B
    // Alespon 8 bajtů dat, ktera jsem poslal
};

/// Struktura pro predani argumentu workerum
struct worker_arg_t {
    /// Maximalni pripustna doba cekani
    struct timeval rttTmval;
};

//class Sniffer: public LockObj {
class Sniffer {
public:
    /**
     * Provede globalni inicializace snifferu
     * @param  opt Argumenty predane programu
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool Init( const opt_t opt );
    /**
     * Spusti Arp sniffer a nastavi vse potrebne
     * @param  iface na teto NIC se bude sniffovat
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool ArpStart( const iface_t iface );
    /**
     * Zastavi Arp sniffer
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool ArpStop( void );
    /**
     * Spusti Icmp sniffer (prijma ECHO dotazy)
     * @param  iface na teto NIC se bude sniffovat
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool IcmpEchoStart( const iface_t iface );
    /**
     * Spust Icmp sniffer, hleda DESTINATION UNREACH zpravy
     * @param  iface na teto NIC se bude sniffovat
     * @param  inAddr Filtruj porty podle teto IP
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool IcmpUdpStart( const iface_t iface, const struct in_addr inAddr );
    /**
    * Spusti Tcp sniffer (prijma SYN + ACK)
    * @param  iface Sniffovani bude probihat na tomto rozhrani
    * @param  inAddr Filtruj porty podle teto IP
    * @return       FALSE pokud vse ok, jinak TRUE
    */
    bool TcpStart( const iface_t iface, const struct in_addr inAddr );
    /**
     * Zastavi Tcp Sniffer
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool TcpStop( void );
    /**
     * Zastavi Icmp sniffer
     * @return  FALSE pokud vse ok, jinak TRUE
     */
    bool IcmpStop( void );
    /**
     * Vrati vektor aktivnich hostu
     * Funkce zpravuje a profiltruje vsechny zaznamy, ktere byly zachyceny
     * @return  Vektor aktivnich hostu
     */

    std::vector<struct in_addr> getOnlineHosts( void );
    std::vector<uint32_t> getOpenUdpPorts( void );
    std::vector<uint32_t> getOpenTcpPorts( void );

    /**
     * Smaz ziskane IP adresy
     */
    void ClearPingRecords( void );
    /**
     * Smaz ziskane UDP porty
     */
    void ClearUdpRecords( void );
    /**
     * Smaz ziskane TCP porty
     */
    void ClearTcpRecords( void );

private:
    /// Nastaveni (argumenty programu)
    opt_t opt;
    /// Sniffing probiha na tomto rozhrani
    static iface_t currNIC;


    /// ARP + ICMP hosti, kteri jsou online
    static std::vector<struct in_addr> recordPing;

    /// Otevrene TCP porty
    static std::vector<uint32_t> recordTcp;

    /// Porty, ktere byly vyhodnoceny jako ZAVRENE,
    /// Prislo ICMP DESTINATION UNREACH
    /// port je FALSE==zavreny, jinak otevreny
    static std::vector<uint32_t> recordUdp;

    /// Bude sniffer prijmat ICMP DESTINATION UNREACH ? (implicitne false == NE)
    static bool acceptUDP;
    /// Sniffer bude prijmat ICMP DESTINATION UNREACH od teto IP
    static struct in_addr currInAddrIP;

    /// Argument pro workery
    worker_arg_t WorkerArg;

// ------------------------------------------------------------------
// 			Cast tridy popisujici sniffovani ARP
// ------------------------------------------------------------------
private:
    /// Indikuje, jestli je worker provedl inicializace a je pripraven
    /// TRUE=Je pripraven FALSE=inicializace probiha
    static bool arpWorkerReady;
    /// Zamek pro workera
    static bool arpLock;
	/// Ovladac vlakna, kter zachytava ARP
	pthread_t arpWorker;

    /**
     * Worker bezi na samostatnem vlakne
     * @param  arg Struktura s argumenty
     * @return     NULL
     */
	static void * ArpWorker( void * arg);
// ------------------------------------------------------------------
// 			Cast tridy popisujici sniffovani ICMP
// ------------------------------------------------------------------
private:
    /// Indikuje, jestli je worker provedl inicializace a je pripraven
    /// TRUE=Je pripraven FALSE=inicializace probiha
    static bool icmpWorkerReady;
    /// Zamek pro workera
    static bool icmpLock;
    /// Ovladac vlakna, ktere zachytava ICMP
	pthread_t icmpWorker;

    /**
     * Worker bezi na samostatnem vlakne
     * @param  arg Struktura s argumenty
     * @return     NULL
     */
	static void * IcmpWorker( void * arg );
    /**
     * Zakladni funkce pro ICMP sniffer
     * @param  iface Sniffovani bude probihat na tomto rozhrani
     * @return       FALSE pokud vse ok, jinak TRUE
     */
    bool IcmpStart( const iface_t iface );
// ------------------------------------------------------------------
// 			Cast tridy popisujici sniffovani TCP
// ------------------------------------------------------------------
private:
    /// Indikuje, jestli je worker provedl inicializace a je pripraven
    /// TRUE=Je pripraven FALSE=inicializace probiha
    static bool tcpWorkerReady;
    /// Zamek pro workera
    static bool tcpLock;
    /// Vlakno, ktere zachytava SYN+ACK odpovedi
    pthread_t tcpWorker;

    /**
     * Worker bezi na samostatnem vlakne
     * @param  arg Struktura s argumenty
     * @return     NULL
     */
    static void * TcpWorker( void * arg );

};	/* class Sniffer*/

#endif	/* SNIFFER_HPP_ */
