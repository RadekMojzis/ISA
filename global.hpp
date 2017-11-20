/**
 * @file   : isamon.hpp
 * @date   : 2017-09-25
 * @author : Martin Pumr
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

#define terror std::cerr << CLR_BOLD << __FILE__ << ":" << __LINE__ << ": " << CLR_RED << "[ ERROR ] " << CLR_RST << CLR_BOLD << strerror(errno) << "(" << errno << "): " << CLR_RST

#ifdef NDEBUG

#define debug if ( 0 ) std::cerr

#else

// debug pro hlavni proces
#define debug std::cerr << CLR_GREEN << __FILE__ << CLR_RST << ":" << __LINE__ << ": " << CLR_YELLOW << "[ DEBUG ] " << CLR_RST

#endif


#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

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
	char name[MAX_IFACE_NAME_BYTES+1];		///< jmeno karty + '\0'
    mac_t mac;          ///< HW adresa karty
    struct in_addr nicInAddr;
    struct in_addr nicMaskInAddr;
    struct in_addr nicNetInAddr;

    /// OBSOLATE
    ip4_t ipAddr;		///< Adresa sitove karty
	ip4_t netAddr;		///< Adresa site ke ketere je karta pripojena
    ip4_t mask;			///< maska site ke ktere je karta pripojena
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
    uint32_t port;
    uint8_t net[4];
    uint8_t mask;
    char * iface;
    uint32_t rtt;
    struct timeval rttTmval;
};

/// Nastavení
struct opt_t {
    flag_t flg;
    value_t val;
};


void showHelp( void );
opt_t parseArgs( int argc, const char ** argv );


// Pretizeni pro lepsi vypisy ...
std::ostream& operator<<(std::ostream&, const uint8_t);     	// uint8_t
std::ostream& operator<<(std::ostream&, const ip4_t ip);    	// IPv4
std::ostream& operator<<(std::ostream&, const mac_t mac);   	// MAC
std::ostream& operator<<(std::ostream&, const iface_t iface);   // MAC
std::ostream& operator<<(std::ostream&, const struct in_addr inaddr);   // IPv4
bool operator==(const ip4_t& a, const ip4_t& b);
bool operator!=(const ip4_t& a, const ip4_t& b);

ip4_t InAddrToIP4( const struct in_addr addr );


#endif /* GLOBAL_HPP_ */
