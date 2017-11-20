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
 * @file    : global.cpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Global definitions
 */

#include <iostream>
#include <cstdint>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

#include "global.hpp"

using namespace std;

ostream& operator<< (ostream& os, const uint8_t val)
{
	os << (unsigned)val;
	return os;
}

ostream& operator<< (ostream& os, const ip4_t ip)
{
	os /*<< setfill('0') << setw(3)*/ << ip.oct[0] << ".";
	os /*<< setfill('0') << setw(3)*/ << ip.oct[1] << ".";
	os /*<< setfill('0') << setw(3)*/ << ip.oct[2] << ".";
	os /*<< setfill('0') << setw(3)*/ << ip.oct[3];

	return os;
}

ostream& operator<< (ostream& os, const mac_t mac)
{
	os << hex << setfill('0') << setw(2) << mac.oct[0] << ":";
	os << hex << setfill('0') << setw(2) << mac.oct[1] << ":";
	os << hex << setfill('0') << setw(2) << mac.oct[2] << ":";
	os << hex << setfill('0') << setw(2) << mac.oct[3] << ":";
	os << hex << setfill('0') << setw(2) << mac.oct[4] << ":";
	os << hex << setfill('0') << setw(2) << mac.oct[5] << dec;

	return os;
}

ostream& operator<< (ostream& os, const iface_t iface)
{
	os << "[" << iface.name << "] ";
	os << "<" << iface.mac << "> ";
	os << "IP=<" << InAddrToIP4(iface.nicInAddr) << "> ";
	os << "Mask=<" << InAddrToIP4(iface.nicMaskInAddr) << "> ";
	os << "NetIP=<" << InAddrToIP4(iface.nicNetInAddr) << "> ";

	return os;
}

ostream& operator<< (ostream& os, const struct in_addr addr)
{
	os << inet_ntoa(addr);
	return os;
}

bool operator<(const ip4_t& a, const ip4_t& b)
{
	for (int i = 0; i < 3; i++) {
		if (a.oct[i] < b.oct[i]) {
			//debug << a << " < " << b << " TRUE\n";
			return true;
		}
		else if (a.oct[i] == b.oct[i]) {
			continue;
		}
		else {
			//debug << a << " < " << b << " FALSE\n";
			return false;
		}
	}
	//debug << a << " < " << b << " FALSE\n";
	return false;
}
bool operator>(const ip4_t& a, const ip4_t& b)
{
	return operator<(b, a);
}
bool operator<=(const ip4_t& a, const ip4_t& b)
{
	return !operator>(a, b);
}
bool operator>=(const ip4_t& a, const ip4_t& b)
{
	return !operator<(a, b);
}
bool operator==(const ip4_t& a, const ip4_t& b)
{
	for (int i = 0; i < 4; i++) {
		if (a.oct[i] != b.oct[i]) {
			return false;
		}
	}

	return true;
}
bool operator!=(const ip4_t& a, const ip4_t& b)
{
	return !operator==(a, b);
}

ip4_t operator&(const ip4_t &lhs, const ip4_t &rhs) // Bitwise and
{
	ip4_t ip = {
		(uint8_t)(lhs.oct[0] & rhs.oct[0]),
		(uint8_t)(lhs.oct[1] & rhs.oct[1]),
		(uint8_t)(lhs.oct[2] & rhs.oct[2]),
		(uint8_t)(lhs.oct[3] & rhs.oct[3]),
	};
	return ip;
}
ip4_t operator~(const ip4_t &rhs) // Bitwise complement
{
	ip4_t ip = {
		(uint8_t)( ~ rhs.oct[0]),
		(uint8_t)( ~ rhs.oct[1]),
		(uint8_t)( ~ rhs.oct[2]),
		(uint8_t)( ~ rhs.oct[3]),
	};
	return ip;
}
ip4_t operator^(const ip4_t &lhs, const ip4_t &rhs) // Bitwise exclusive or
{
	ip4_t ip = {
		(uint8_t)(lhs.oct[0] ^ rhs.oct[0]),
		(uint8_t)(lhs.oct[1] ^ rhs.oct[1]),
		(uint8_t)(lhs.oct[2] ^ rhs.oct[2]),
		(uint8_t)(lhs.oct[3] ^ rhs.oct[3]),
	};
	return ip;
}
ip4_t operator|(const ip4_t &lhs, const ip4_t &rhs) // Bitwise or
{
	ip4_t ip = {
		(uint8_t)(lhs.oct[0] | rhs.oct[0]),
		(uint8_t)(lhs.oct[1] | rhs.oct[1]),
		(uint8_t)(lhs.oct[2] | rhs.oct[2]),
		(uint8_t)(lhs.oct[3] | rhs.oct[3]),
	};
	return ip;
}

ip4_t InAddrToIP4( const struct in_addr addr )
{
	unsigned tmp[4] = { 0 };
	sscanf(inet_ntoa(addr), "%u.%u.%u.%u", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
	ip4_t ip = {
		(uint8_t)tmp[0],
		(uint8_t)tmp[1],
		(uint8_t)tmp[2],
		(uint8_t)tmp[3]
	};

	return ip;
}

struct in_addr IP4ToInAddr( const ip4_t ip )
{
	struct in_addr addr;
	char tmp[32] = { 0 };

	sprintf(tmp, "%d.%d.%d.%d", ip.oct[0], ip.oct[1], ip.oct[2], ip.oct[3]);
	inet_aton(tmp, &addr);

	return addr;
}

/// Pripoj soket k NIC
bool bindSockToIface( int * sock, const char * name )
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl (*sock, SIOCGIFINDEX, &ifr) < 0) {
		terror << "Cannot get ifr stats\n";
		return true;
	}

	if (setsockopt(*sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		return true;
	}

	return false;
}
