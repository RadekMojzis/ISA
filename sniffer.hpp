

#ifndef SNIFFER_HPP_
#define SNIFFER_HPP_

#include <pthread.h>

#include <vector>
#include <sys/time.h>
#include <netinet/if_ether.h>   // struct ether_arp
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO

#include "global.hpp"
#include "lock.hpp"
#include "packet.hpp"

 /// Odpoved, ktera prisla jako vysledek UDP zadosti na port
 struct udp_answer_t {
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

//class Sniffer: public LockObj {
class Sniffer {
private:
	static std::vector<std::string> recordArp;    ///< Vysledky skenu
	static std::vector<std::string> recordIcmp;   ///< Vysledky skenu
    static std::vector<unsigned> recordUdp;           ///< Vysledky skenu

	// ~~~ OPT
	static iface_t iface;                  ///< Svazani soketu s NIC
	static bool arpLock;                   ///< Zamky pro workery
	static bool icmpLock;
	static bool arpWorkerReady;            ///< Jsou workeri pripraveni?
	static bool icmpWorkerReady;

    /// Sniffer bude pracovat nad temito IP
    static struct in_addr currInAddrIP;
    ip4_t currIP;
	// ~~~ ARP
	pthread_t arpWorker;
	bool ArpStart( void );
	bool ArpStop( void );
	static void * ArpWorker( void * arg);


    //TODO FIXME přivázat TCP soket k IFACE


    // ~~~ ICMP
	pthread_t icmpWorker;
	bool IcmpStart( void );
	bool IcmpStop( void );
	static void * IcmpWorker( void * arg);

    bool Ready( void );

public:
	void Init( const iface_t iface);   ///< Pripoj se k NIC
    bool SetIpOfInterest( const ip4_t ip4 );    ///< Scanner bude pracovat nad touto IP
	bool Start( void );                ///< Zacni
	bool Stop( void );
    bool IsHostOnline( void );
	bool FlushAll( void );
    bool FlushUdp( void );
    bool printResults( void );
    bool printUdpResults( void );
};	/* class Sniffer*/

#endif	/* SNIFFER_HPP_ */
