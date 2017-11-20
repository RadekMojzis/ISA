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
 * @file    : global.hpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Global definitions header file
 */

#ifndef GLOBAL_HPP_
#define GLOBAL_HPP_

/// http://elixir.free-electrons.com/linux/v3.19/source/include/linux/netdevice.h#L1492
#define MAX_IFACE_NAME_BYTES     15

#define CLR_RED			"\x1b[31m"
#define CLR_GREEN		"\x1b[32m"
#define CLR_YELLOW		"\x1b[33m"
#define CLR_RST			"\x1b[0m"
#define CLR_BOLD		"\x1b[1m"

enum RCODES {
    ERR_ARGUMENTS = 10,
};

#include <iostream>

/// Error macro
#define terror std::cerr << CLR_BOLD << __FILE__ << ":" << __LINE__ << ": " << CLR_RED << "[ ERROR ] " << CLR_RST << CLR_BOLD << strerror(errno) << "(" << errno << "): " << CLR_RST

#ifdef NDEBUG

#define debug if ( 0 ) std::cerr

#else

/// Debug macro
#define debug std::cerr << CLR_GREEN << __FILE__ << CLR_RST << ":" << __LINE__ << ": " << CLR_YELLOW << "[ DEBUG ] " << CLR_RST

#endif

#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <string.h>

/// Struktura pro IPv4 zaznam
struct ip4_t {
    uint8_t oct[4];		///< jednolive oktety
};

/// Struktura pro MAC zaznam
struct mac_t {
    uint8_t oct[6];		///< jednolive oktety
};

/// Zaznam o informaci o karte
struct iface_t {
    /// Jmeno karty + '\0'
	char name[MAX_IFACE_NAME_BYTES+1];
    /// HW adresa karty
    mac_t mac;
    /// Adresa sitove karty
    struct in_addr nicInAddr;
    /// Maska site ke ktere je karta pripojena
    struct in_addr nicMaskInAddr;
    /// Adresa site ke ketere je karta pripojena
    struct in_addr nicNetInAddr;
};

/// Vlajky pro nastaveni
struct flag_t {
    bool help;      ///< Vypíše help screen
    bool tcp;       ///< Použije pro sken TCP
    bool udp;       ///< Použije pro sken UDP
    bool port;      ///< Port který se bude skenovat, pokud není zadán, skenuje celý rozsah
    bool net;       ///< Adresa sítě, která se bude skenovat
    bool iface;     ///< iface pro skenování
    bool wait;      ///< Doba v ms, po kterou se bude čekat na port
};

// jednolive hodnoty nastaveni
struct value_t {
    uint32_t port;      ///< -p
    ip4_t net;          ///< -n
    ip4_t mask;         ///< -n
    char * iface;       ///< -i
    uint32_t rtt;       ///< -w
    struct timeval rttTmval;
};

/// Nastavení
struct opt_t {
    flag_t flg;
    value_t val;
};

// Pretizeni pro lepsi vypisy ...
std::ostream& operator<<(std::ostream&, const uint8_t);     	// uint8_t
std::ostream& operator<<(std::ostream&, const ip4_t ip);    	// IPv4
std::ostream& operator<<(std::ostream&, const mac_t mac);   	// MAC
std::ostream& operator<<(std::ostream&, const iface_t iface);   // MAC
std::ostream& operator<<(std::ostream&, const struct in_addr inaddr);   // IPv4
bool operator<(const ip4_t& a, const ip4_t& b);
bool operator>(const ip4_t& a, const ip4_t& b);
bool operator<=(const ip4_t& a, const ip4_t& b);
bool operator>=(const ip4_t& a, const ip4_t& b);
bool operator==(const ip4_t& a, const ip4_t& b);
bool operator!=(const ip4_t& a, const ip4_t& b);

ip4_t operator&(const ip4_t &lhs, const ip4_t &rhs); // Bitwise and
ip4_t operator~(const ip4_t &rhs); // Bitwise complement
ip4_t operator^(const ip4_t &lhs, const ip4_t &rhs); // Bitwise exclusive or
ip4_t operator|(const ip4_t &lhs, const ip4_t &rhs); // Bitwise or

ip4_t InAddrToIP4( const struct in_addr addr );
bool bindSockToIface( int * sock, const char * name );
struct in_addr IP4ToInAddr( const ip4_t ip );

#endif /* GLOBAL_HPP_ */
