


#ifndef TARGET_HPP_
#define TARGET_HPP_

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "global.hpp"
#include "packet.hpp"

/// Argumenty pro TCP workery
struct tcpScan_WorkerArg_t {
	struct in_addr dstInAddr;
	struct timeval tmout;
	bool * results;
	unsigned portFirst;
};

// Trida pro praci s IP adresou
class Target {
	//friend class Packet;
private:
	// >>> Staticke promenne ... >>>
	static unsigned timeout;        // Kolik ms se bude cekat (ARP, ICMP, port)
	// <<< Staticke promenne <<<

	struct sockaddr_ll sockLLDesc;      // Popis soketu na urovni sitove vrstvy
	struct in_addr dstInAddr;
	struct ip4_t dstIP;

	int sockCONF;  // Pro konfiguraci rozhrani atd.
	// >>> Vystupni sokety >>>
	int sockTCP;        // TCP
	int sockUDP;        // UDP
	int sockARP;        // ICMP
	int sockICMP;       // ARP
	// <<< Vystupni sokety <<<

	// Otestuj jeden port
	bool tryTcpPortWorker( void );
	bool bindOutputSocketsToIface( const char * ifaceName );
	bool tcpParallelScan( const unsigned portFirst=1, const unsigned portLast=65535);
	bool tcpSingleScan( const unsigned port );
public:
	Target( void );
	bool broadcastPingAllowed;

	// >>> Nastaveni cile >>>
	// Volano jednou za scan
	bool setupSrcIface( const iface_t iface );
	bool openSockets( void );
	bool closeSockets( void );
	bool setupSockets( const char * ifaceName );
	bool setWaitTimeMS( const unsigned ms );
	// Volano nad kazdym cilem
	bool setDstAddr( const ip4_t ip4 );
	void clear( void );
	// <<< Nastaveni cile <<<

	// >>> Otestuj cil >>>
	bool pingICMP( void );
	bool pingICMPBroadcast( const ip4_t ip );
	bool pingARP( const iface_t iface );
	bool tryTcpPorts( const unsigned portFirst=1, const unsigned portLast=65535 );
	bool tryUdpPorts( const unsigned portFirst=1, const unsigned portLast=65535 );
	// <<< Otestuj cil <<<
};

#endif /* TARGET_HPP_ */
