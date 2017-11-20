

#include <cerrno>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <net/if.h>             // struct ifreq
#include <ifaddrs.h>
#include <sys/ioctl.h>          // ioctl()
#include <sys/types.h>
#include <arpa/inet.h>          // in_addr_t, htons
#include <net/ethernet.h>       // ETHER_ADD_LEN, ETH_P_*
#include <netpacket/packet.h>   // struct sockaddr_ll

// >>> Knihovny projektu >>>
#include "global.hpp"
#include "target.hpp"
#include "packet.hpp"
#include "scanner.hpp"
#include "sniffer.hpp"
// <<< Knihovny projektu <<<

Scanner::Scanner( void )
{
}

// >>> Lokalni staticke funkce >>>
/**
 * Je skenovana sit lokalni ?
 * @return  TRUE sit je lokalni, jinak FALSE
 */
static bool isNetLocal( void )
{
	return false;
}

// <<< Lokalni staticke funkce <<<
// >>> Tridni funkce >>>

// <<< Tridni funkce <<<

bool Scanner::Init( const iface_t iface )
{
	errno = 0;

	this->iface = iface;

	assert(errno == 0);
	return false;
}

bool Scanner::Start( void )
{
	// ~~~ Postupne oskenuj vsechny subnety
	for (auto it = begin(this->ifaces); it != end(this->ifaces); it++) {
		// Nastav skenner pro skenovani site na dane iface
		if (this->initNet(&(*it))) {
			terror << "Cannot initialize subnet on " << it->name << "\n";
			continue;
		}

		if (this->scanNet()) {
			terror << "Error while scanning subnet on " it->name << "\n";
		}
	}

	return false;
}

bool Scanner::initNet( void )
{
	debug << "Initializing net ...\n";

	// Preved masku z argumentu, nemuze by vetsi jak 30
	uint32_t m = 0xFFFFFFFF << (32 - this->opt.val.mask);
	ip4_t maskIP = {
		(uint8_t)(0xFF & (m >> 24)),
		(uint8_t)(0xFF & (m >> 16)),
		(uint8_t)(0xFF & (m >> 8)),
		(uint8_t)(0xFF & m),
	};

	// ~~~ Nastav privatni promenne
	this->netIP4First = InAddrToIP4(iface.nicNetInAddr);
	this->netIP4Last = {
		this->netIP4First[0] | ~ maskIP.oct[0],
		this->netIP4First[1] | ~ maskIP.oct[1],
		this->netIP4First[2] | ~ maskIP.oct[2],
		this->netIP4First[3] | ~ maskIP.oct[3],
	}

	debug << "Net first IP : " << this->netIP4First << "\n";
	debug << "Net last IP  : " << this->netIP4Last << " (broadcast)\n";

	// ~~~ Nastav NIC pro ARP dotazy
	if (this->setSrcIfaceLL()) {
		terror << "Cannot set socket Link Layer for ARP requests\n";
		return true;
	}

	return false;
}

bool Scanner::setSrcIfaceLL( void );
{
	errno = 0;

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	memset(&this->sockLLDesc, 0, sizeof(struct sockaddr_ll));

	debug << "Setting IFREQ stats for device "<<this->currNic->name<<" ...\n";
	snprintf( ifr.ifr_name, sizeof(ifr.ifr_name), "%s", this->currNic->name );
	if ( ioctl(this->sockCONF, SIOCGIFHWADDR, &ifr) < 0 ) {
		terror << "Cannot set IFR\n";
		return true;
	}

	memcpy(this->sockLLDesc.sll_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_BYTES);

	// Nastaveni linkove vrstvy soketu
	debug << "Setting Link layer interface to " << this->currNic->name << "\n";
	if ((this->sockLLDesc.sll_ifindex = if_nametoindex(iface.name)) == 0) {
		terror << "\n";
		return true;
	}

	this->sockLLDesc.sll_family = AF_PACKET;
	this->sockLLDesc.sll_halen = HW_ADDR_BYTES;
	this->sockLLDesc.sll_protocol = htons(ETH_P_ARP);
	this->sockLLDesc.sll_hatype = htons(ARPHRD_ETHER);
	this->sockLLDesc.sll_pkttype = (PACKET_BROADCAST);

	return false;
}

bool Scanner::scanNet( void )
{
	errno = 0;
	debug << "Scaning net attached to " << this->iface->name << " ...\n";

	Target target;
	Sniffer sniffer;

	// Spusteni vlaken snifferu
	sniffer.Init(iface);
	if (sniffer.Start()) {
		terror << "Failed to start Sniffer\n";
		return true;
	}

	// Otevreni vystupnich soketu
	if (target.openSockets()) {
		return true;
	}

	target.setWaitTimeMS( this->opt.val.wait );

	// Svazani soketu se sitovym rozhranim
	if (target.setupSockets(iface.name)) {
		target.closeSockets();
		return true;
	}

	int i = this->netIP4First.oct[0];
	int j = this->netIP4First.oct[1];
	int k = this->netIP4First.oct[2];
	int l = this->netIP4First.oct[3];
	ip4_t currIP;

	debug "Starting scan ...\n";
	for ( ; i < 256; i++) {
		for ( ; j < 256; j++) {
			for ( ; k < 256; k++) {
				for ( ; l < 256; l++) {
					currIP = { (uint8_t)i, (uint8_t)j, (uint8_t)k, (uint8_t)l};
					debug << " // " << currIP << "\n";

					// nastav cil
					target.clear();
					target.setDstAddr( currIP );
					sniffer.SetIpOfInterest( currIP );

					// zacni skenovat
					// vysledek ARP a ICMP prebira sniffer
					target.pingICMP();
					if ( target.IsIpLocal(currIP) ) {
						target.pingARP(iface);
					}

					// Pokud je IP online, spust skenovani portu (RFC 1122)
					if (sniffer.IsHostOnline()) {
						if ( this->opt.flg.udp ) {
							if (this->opt.flg.port) {
								target.tryUdpPorts(this->opt.val.port, this->opt.val.port);
							} else {
								target.tryUdpPorts();
							}
							usleep(this->opt.val.wait * 1000);
							sniffer.printUdpResults();
							sniffer.FlushUdp();
						}

						if ( this->opt.flg.tcp ) {
							if (this->opt.flg.port) {
								target.tryTcpPorts(this->opt.val.port, this->opt.val.port);
							} else {
								target.tryTcpPorts();
							}
						}
					}

					// Ukonci sken pokud IP byla posledni
					if ( this->netLastIP == currIP ) {
						debug << "Running cleaning rutines and final Blow...\n";
						usleep(this->opt.val.wait * 1000);
						target.closeSockets();
						sniffer.Stop();
						debug << "Flushing list of online hosts ...\n";
						//sniffer.printResults();
						sniffer.FlushAll();
						debug << "Sken on ~ "  << iface.name << " ~ done\n";
						return false;
					}
				}
				l = 0;
			}
			k = 0;
		}
		j = 0;
	}

	// Tady ziji draci, sem by se program nikdy nemel dostat

	return false;
}

bool Scanner::setIPRange( void )
{
	errno = 0;
	debug << "Setting IP range ...\n";

	uint32_t m;
	if (this->opt.val.mask > 31) {
		m = 0x00;   // XXX Protože C nepodporuje shift > 32 bitů
	} else {
		m = 0xFFFFFFFF << (32 - this->opt.val.mask);
	}

	this->netMask = {
		(uint8_t)(0xFF & (m >> 24)),
		(uint8_t)(0xFF & (m >> 16)),
		(uint8_t)(0xFF & (m >> 8)),
		(uint8_t)(0xFF & m),
	};

	// Broadcast site
	this->netLastIP = {
		(uint8_t)(this->opt.val.net[0] | ~ this->netMask.oct[0]),
		(uint8_t)(this->opt.val.net[1] | ~ this->netMask.oct[1]),
		(uint8_t)(this->opt.val.net[2] | ~ this->netMask.oct[2]),
		(uint8_t)(this->opt.val.net[3] | ~ this->netMask.oct[3]),
	};

	this->netFirstIP = {
		this->opt.val.net[0],
		this->opt.val.net[1],
		this->opt.val.net[2],
		this->opt.val.net[3],
	};

	debug << "Net first IP : " << this->netFirstIP << "\n";
	debug << "Net last IP  : " << this->netLastIP << " (broadcast)\n";
	debug << "Net mask     : " << this->netMask << "\n";

	return false;
}
