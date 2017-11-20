

#include <chrono>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>

#include <arpa/inet.h>          // in_addr_t, htons
#include <linux/if_ether.h>     // ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003

#include <sys/ioctl.h>          // ioctl()
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>             // struct ifreq
#include <net/ethernet.h>       // ETHER_ADD_LEN, ETH_P_*

#include <netinet/in.h>
#include <netinet/if_ether.h>   // struct ether_arp

#include <netpacket/packet.h>   // struct sockaddr_ll
// <<< Knihovny pro ARP vrstvu <<<

// Lokalni vypnuti debugovych hlaseni
//#define NDEBUG

// >>> Knihovny projektu >>>
#include "global.hpp"
#include "target.hpp"
#include "packet.hpp"
#include "lock.hpp"
// <<< Knihovny projektu <<<

#define PORT_FIRST				1	///< Prvni skenovany port
#define PORT_LAST			65535	///< Posledni skenovany port
#define PORTS_PER_WORKER	 8192	///< Pocet portu na vlakno

// >>> Staticke promenne trid >>>
// >>> ... skenovani portu >>>
unsigned Target::timeout = 1000;	///< Kolik ms se bude cekat na port
// <<< ... skenovani portu <<<
// <<< Staticke promenne trid <<<


Target::Target( void )
{
	// Public
	this->broadcastPingAllowed = false;
}

// >>> Nastaveni cile >>>

bool Target::openSockets( void )
{
	errno = 0;

	this->sockCONF = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if ( sockCONF < 0 ) {
		terror << "Sock CONF\n";
		goto ERR_SOCK_CONF;
	}
	this->sockUDP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sockUDP < 0 ) {
		terror << "Sock UDP\n";
		goto ERR_SOCK_UDP;
	}
	this->sockARP = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if ( sockARP < 0 ) {
		terror << "Sock ARP\n";
		goto ERR_SOCK_ARP;
	}
	this->sockICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sockICMP < 0 ) {
		terror << "Sock ICMP\n";
		goto ERR_SOCK_ICMP;
	}

	return false;

	ERR_SOCK_ICMP:
	close(this->sockARP);
	ERR_SOCK_ARP:
	close(this->sockUDP);
	ERR_SOCK_UDP:
	close(this->sockCONF);
	ERR_SOCK_CONF:
	terror << "Socket opening failed\n";

	return true;
}

bool Target::closeSockets( void )
{
	errno = 0;

	close(this->sockCONF);
	close(this->sockUDP);
	close(this->sockARP);
	close(this->sockICMP);

	return false;
}

bool Target::setupSockets( const char * ifaceName )
{
	errno = 0;

	int broadcastPermission = 1;
	if (setsockopt(this->sockICMP, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastPermission, sizeof(broadcastPermission)) < 0) {
		terror << "ICMP Broadcast ping not allowed\n";
		this->broadcastPingAllowed = false;
	} else {
		this->broadcastPingAllowed = true;
	}

	if (setsockopt(this->sockUDP, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastPermission, sizeof(broadcastPermission)) < 0) {
		terror << "UDP Broadcast not allowed\n";
	}

	// Svazani soketu s kartou
	if (this->bindOutputSocketsToIface( ifaceName )) {
		terror << "Cannot bind output sockets to iface " << ifaceName << "\n";
		return true;
	}

	return false;
}

bool Target::bindOutputSocketsToIface( const char * ifaceName )
{
	errno = 0;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	// Ziskej informace o karte
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifaceName);
	if (ioctl (sockCONF, SIOCGIFINDEX, &ifr) < 0) {
		terror << "Cannot get ifr stats\n";
		return true;
	}

	// Pripoj sokety ke karte
	if (setsockopt(sockUDP, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		goto ERR_BIND;
	}
	if (setsockopt(sockARP, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		goto ERR_BIND;
	}
	if (setsockopt(sockICMP, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		goto ERR_BIND;
	}

	return false;

	ERR_BIND:
	terror << "Binding of output sockets failed\n";

	return true;
}

bool Target::setWaitTimeMS( const unsigned int ms )
{
	errno = 0;

	Target::timeout = ms;

	return false;
}


bool Target::setDstAddr( const ip4_t ip4 )
{
	errno = 0;

	this->dstIP = ip4;

	char tmp[16] = { 0 };
	sprintf(tmp, "%d.%d.%d.%d", ip4.oct[0], ip4.oct[1], ip4.oct[2], ip4.oct[3]);
	if ( ! inet_aton(tmp, &(this->dstInAddr)) ) {
		return true;
	}

	return false;
}

void Target::clear( void )
{
	memset(&this->dstIP, 0, sizeof(this->dstIP));
}

// <<< Nastaveni cile <<<

// >>> Otestuj cil >>>

bool Target::pingARP( const iface_t iface )
{
	errno = 0;

	Packet pckt;
	pckt.forgeArp( iface, this->dstIP );

	//debug << "Sanding " << pckt.packet.len << " Bytes ARP to " << this->dstIP<<"\n";

	if (sendto(this->sockARP, pckt.packet.data, pckt.packet.len, 0, (struct sockaddr *)&this->sockLLDesc, sizeof(struct sockaddr_ll)) <= 0) {
		terror << "Cannot send forged packet\n";
		return true;
	}

	return false;
}

bool Target::pingICMPBroadcast( const ip4_t ip )
{
	errno = 0;

	Packet pckt;
	pckt.forgeIcmpEcho();

	debug << "Sanding " << pckt.packet.len << " Bytes ICMP to Broadcast " << ip<<"\n";

	struct in_addr inAddr;

	char tmp[16] = { 0 };
	sprintf(tmp, "%d.%d.%d.%d", ip.oct[0], ip.oct[1], ip.oct[2], ip.oct[3]);
	if ( ! inet_aton(tmp, &inAddr) ) {
		terror << "Cannot convert broadcast IP\n";
		return true;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr = inAddr;

	if (sendto(this->sockICMP, pckt.packet.data, pckt.packet.len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) <= 0) {
		terror << "Cannot send forged broadcast packet\n";
		return true;
	}

	return false;
}

bool Target::pingICMP( void )
{
	errno = 0;

	Packet pckt;
	pckt.forgeIcmpEcho();

	debug << "Sanding " << pckt.packet.len << " Bytes ICMP to " << this->dstIP<<"\n";

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr = this->dstInAddr;

	if (sendto(this->sockICMP, pckt.packet.data, pckt.packet.len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) <= 0) {
		terror << "Cannot send forged packet\n";
		return true;
	}

	return false;
}

static bool tryTcpPort( const struct sockaddr_in addr, const struct timeval tmout )
{
	errno = 0;

	int res, valopt;
	long arg;
	fd_set myset;
	struct timeval tv = tmout;
	socklen_t lon;
	bool portIsOpen = true;		// Predpokladam, ze je otevreny
	int soc = socket(AF_INET, SOCK_STREAM, 0);
	if (soc < 0) {
		terror << "Cannot open TCP scan socket\n";
		return false;
	}

	// >>> http://developerweb.net/viewtopic.php?id=3196 >>>
	// Set non-blocking
	arg = fcntl(soc, F_GETFL, NULL);
	arg |= O_NONBLOCK;
	fcntl(soc, F_SETFL, arg);

	// Trying to connect with timeout
	res = connect(soc, (struct sockaddr *)&addr, sizeof(addr));
	if (res < 0) {
		/// !!! ERRNO je thread-local setting podle ISO-C
		if (errno == EINPROGRESS) {
			// tv.tv_sec = (unsigned)(this->timeout / 1000);
			// tv.tv_usec = (this->timeout % 1000) * 1000;
			FD_ZERO(&myset);
			FD_SET(soc, &myset);
			if (select(soc + 1, NULL, &myset, NULL, &tv) > 0) {
				lon = sizeof(int);
				getsockopt(soc, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
				if ( valopt ) {
					//terror <<"TCP port connect() failed\n";
					portIsOpen = false;
					goto PORT_CLOSED;
				}
			}
			else {
				//debug << "Timeout or error()\n";
				portIsOpen = false;
				goto PORT_CLOSED;
			}
		}
		else {
			//debug << "Error connecting\n";
			portIsOpen = false;
			goto PORT_CLOSED;
		}
	}

	// Set to blocking mode again...
	PORT_CLOSED:
	arg = fcntl(soc, F_GETFL, NULL);
	arg &= (~O_NONBLOCK);
	fcntl(soc, F_SETFL, arg);
	close(soc);
	// <<< http://developerweb.net/viewtopic.php?id=3196 <<<

	return portIsOpen;
}

bool Target::tcpSingleScan( const unsigned port )
{
	errno = 0;

	struct sockaddr_in addr;
	struct timeval tmout;

	addr.sin_family = AF_INET;
	addr.sin_addr = this->dstInAddr;
	addr.sin_port = htons( port );
	tmout.tv_sec = (unsigned)(this->timeout / 1000);
	tmout.tv_usec = (this->timeout % 1000) * 1000;

	if (tryTcpPort(addr, tmout)) {
		std::cout << this->dstIP << " TCP " << port << "\n";
	}

	return false;
}

bool Target::tryTcpPorts( const unsigned portFirst, const unsigned portLast )
{
	errno = 0;

	if (portFirst == portLast) {
		this->tcpSingleScan(portFirst);
	} else {
		this->tcpParallelScan();
	}

	return false;
}

/// Inicializuj TCP socket
// static int tcpScan_Worker_InitTcpSock( void )
// {
// 	int sock = socket(AF_INET, SOCK_STREAM, 0);
// 	if ( sock < 0) {
// 		terror << "Cannot initialize TCP socket\n";
// 		return -1;
// 	}
//
//  	// if (setsockopt(sockTCP, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
// 	// 	terror << "Cannot bind TCP sock to iface"
// 	// 	return -1;
// 	// }
//
// 	return sock;
// }

static void * tcpScan_Worker( void * workerArg )
{
	errno = 0;

	tcpScan_WorkerArg_t * arg = (tcpScan_WorkerArg_t *)workerArg;

	unsigned portFirst = arg->portFirst;
	unsigned portLast = arg->portFirst + PORTS_PER_WORKER;
	if (portFirst < 1) portFirst = 1;
	if (portLast > 65535) portLast = 65535;

	// int sock = tcpScan_Worker_InitTcpSock();
	// if (sock < 0) {
    //
	// }


	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr = arg->dstInAddr;

	//debug << "Worker range set to "<<arg->portFirst<<"-"<<arg->portFirst+PORTS_PER_WORKER<<"\n";
	for (unsigned i = portFirst; i <= portLast; i++) {
		addr.sin_port = htons( i );
		arg->results[i] = tryTcpPort(addr, arg->tmout);
		if (arg->results[i]) {
			debug << "TCP " << i << " Open\n";
		}
	}

	return NULL;
}

bool Target::tcpParallelScan( const unsigned portFirst, const unsigned portLast)
{
	errno = 0;
	bool portStatus[65536] = { false };

	debug << "Initializing TCP scanner, Expecting "<<65535 / PORTS_PER_WORKER +1<<" threads\n";

	std::vector<pthread_t> threads;
	tcpScan_WorkerArg_t arg;
	pthread_t thr;

	// Spawn vlaken
	for (unsigned i = portFirst; i <= portLast; i += PORTS_PER_WORKER +1) {
		debug << "Spawning TCP worker ["<<i<<"-"<<i+PORTS_PER_WORKER<<"]\n";

		arg.dstInAddr = this->dstInAddr;
		arg.tmout.tv_sec = (unsigned)(this->timeout / 1000);
		arg.tmout.tv_usec = (this->timeout % 1000) * 1000;
		arg.results = portStatus;
		arg.portFirst = i;

		if (pthread_create(&thr, NULL, tcpScan_Worker, (void *)&arg)) {
			terror << "Cannot spawn TCP worker\n";
		}

		threads.push_back(thr);
	}

	// Join vlaken
	debug << "Waiting for TCP workers ...\n";
	for ( auto it = threads.begin(); it != threads.end(); it++ ) {
		debug << "TCP Worker joined ...\n";
		pthread_join(*it, NULL);
	}

	// Vytiskni vysledky
	debug << "Flushing TCP results ...\n";
	for (unsigned i = portFirst; i <= portLast; i++) {
		if ( portStatus[i] ) std::cout << this->dstIP << " TCP " << i <<"\n";
	}

	return false;
}

bool Target::tryUdpPorts( const unsigned portFirst, const unsigned portLast )
{
	errno = 0;

	char buffer[16] = { 0 };
	struct sockaddr_in addr;

	addr.sin_addr = this->dstInAddr;
	addr.sin_family = AF_INET;

	debug << "Trying UDP port/s ["<<portFirst<<"-"<<portLast<<"]\n";
	for (unsigned i = portFirst; i <= portLast; i++ ) {
		debug << "// " << this->dstIP << " UDP " << i << "\r";
		addr.sin_port = htons( i );

		// Pro kontrolu pridej do do payloadu cislo skenovaneho portu
		sprintf(buffer, "%u", i);
		if (sendto(this->sockUDP, buffer, 8, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			terror << "Cannot send UDP request to port " << i << "\n";
			//return true;
		}
	}

	return false;
}

// <<< Otestuj cil <<<
