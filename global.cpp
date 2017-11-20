

#include <iostream>
#include <cstdint>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	os << "IP=<" << iface.ipAddr << "> ";
	os << "Mask=<" << iface.mask << "> ";
	os << "NetIP=<" << iface.netAddr << "> ";

	return os;
}

ostream& operator<< (ostream& os, const struct in_addr addr)
{
	os << inet_ntoa(addr);
	return os;
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

ip4_t InAddrToIP4( const struct in_addr addr )
{
	unsigned tmp[4];
	sscanf(inet_ntoa(addr), "%u.%u.%u.%u", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
	ip4_t ip = {
		(uint8_t)tmp[0],
		(uint8_t)tmp[1],
		(uint8_t)tmp[2],
		(uint8_t)tmp[3]
	};

	return ip;
}
