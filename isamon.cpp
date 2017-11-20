
#include <net/if.h>
#include <pcap.h>
#include <cstring>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <unistd.h>


#include "global.hpp"
#include "isamon.hpp"


// >>> Lokalni staticke funkce >>>

/// Vytiskni napovedu
static void showHelp( void )
{
    using namespace std;

    cout << endl;
    cout << " USAGE: ./isamon [switches] -n <net/mask>" << endl;
    cout << endl;
    cout << " -t                          : Use TCP protocol" << endl;
    cout << " -u                          : Use UDP protocol" << endl;
    cout << " -n, --network  <net/mask>   : Scan this network" << endl;
    cout << " -i, --interface <iface>     : NIC used for scan" << endl;
    cout << " -w, --wait <ms>             : Wait time for port response" << endl;
    cout << " -h, --help                  : Show this help screen" << endl;
    cout << endl;
    cout << " example: ./isamon -i eth0 -t -p 22 -n <10.0.0.1/24>" << endl;
    cout << endl;
}

// Najde NIC IP, NET IP, NET mask, ...
static bool getIfaceStats( iface_t & iface, const char * name )
{
    errno = 0;
    debug << "Gathering stats from [" << name << "]\n";

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifreq));

    int sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ALL) );
    //int sock = socket( AF_INET, SOCK_DGRAM, 0 );
    if (sock < 0) goto ERR_SOCK;

    strncpy(ifr.ifr_name, name, MAX_IFACE_NAME_BYTES);

    // ~~~ Ziskej MAC
    debug << "[" << name << "] MAC\n";
    if ( ioctl (sock, SIOCGIFHWADDR, &ifr) < 0 ) goto ERR_IOCTL;
    for (int i = 0; i < 6; i++ ) iface->mac.oct[i] = ifr.ifr_hwaddr.sa_data[i];

    // ~~~ Najdi iface IP
    debug << "[" << name << "] Iface IP\n";
    if ( ioctl (sock, SIOCGIFADDR, &ifr) < 0 ) goto ERR_IOCTL;
    iface->nicInAddr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

    // ~~~ Najdi masku site
    debug << "[" << it->name << "] Net mask\n";
    if ( ioctl( sock, SIOCGIFNETMASK, &ifr ) < 0 ) goto ERR_IOCTL;
    iface->nicMaskInAddr = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr;

    // ~~~ Najdi adresu site
    debug << "[" << it->name << "] Net addr\n";
    iface->nicNetInAddr = iface->nicInAddr & iface->nicMaskInAddr;

    close(sock);

    assert(errno == 0);
    return false;
}

// <<< Lokalni staticke funkce <<<
// >>> Tridni funkce >>>

bool Isamon::parseArgs( const int argc, const char ** argv )
{
    opt_t opt;
    memset(&opt, false, sizeof(opt_t));

    // Defaultni nastaveni
	opt.val.wait = 1000;   // Cekej 1 sekundu

    for (int i = 1; i < argc; i++)
    {
        std::string tmp = std::string(argv[i]);

        debug << "Processing arg_" << i << " [" << tmp << "]\n";

        if (tmp == "-t") {
            opt.flg.tcp = true;
        }
        else if (tmp == "-u") {
            opt.flg.udp = true;
        }
        else if (tmp == "-h" || tmp == "--help") {
            opt.flg.help = true;
            showHelp();
            exit(EXIT_SUCCESS);
        }

        else if (tmp == "-n" || tmp == "--network") {
            if (argc >= ++i +1) {
                opt.flg.net = true;
                int val[5] = { -1 };
				char tst;		// ochrana pred 10.42.0.100/24axaxax
                int scaned = sscanf(argv[i], "%d.%d.%d.%d/%d%c", &val[0], &val[1], &val[2], &val[3], &val[4], &tst);
                debug << "scaned elements=" << scaned << "\n";
                debug << val[0]<<"."<<val[1]<<"."<<val[2]<<"."<<val[3]<<"/"<<val[4]<<"\n";

                if (    scaned != 5                 ||  \
                        0 > val[0] || val[0] > 255  ||  \
                        0 > val[1] || val[1] > 255  ||  \
                        0 > val[2] || val[2] > 255  ||  \
                        0 > val[3] || val[3] > 255  ||  \
                        0 > val[4] || val[4] > 32   ||  \
                        0                               \
                ) {
                    terror << "IP address in bad format\n";
                    std::exit(EXIT_FAILURE);
                }

                opt.val.net[0] = val[0];
                opt.val.net[1] = val[1];
                opt.val.net[2] = val[2];
                opt.val.net[3] = val[3];
                opt.val.mask = val[4];
            } else {
                terror << "-n needs additional value\n";
                std::exit(EXIT_FAILURE);
            }
        }
        else if (tmp == "-i" || tmp == "--interface") {
            if (argc >= ++i +1) {
                opt.flg.iface = true;
                opt.val.iface = (char *) argv[i];
                if (strlen(opt.val.iface) > MAX_IFACE_NAME_BYTES) {
                    terror << "Iface name too long, maxium is " << MAX_IFACE_NAME_BYTES << " chars\n";
                    std::exit(EXIT_FAILURE);
                }
            } else {
                terror << "-i needs additional value\n";
                std::exit(EXIT_FAILURE);
            }
        }
        else if (tmp == "-p" || tmp == "--port") {
            if (argc >= ++i +1) {
                opt.flg.port = true;
                char *end = NULL;
                long port = std::strtol(argv[i], &end, 10);

                if ( *end != '\0' || port < 1 || port > 65535 || errno != 0) {
                    terror << "Invalid port number\n";
                    std::exit(EXIT_FAILURE);
                }

                opt.val.port = port;
            } else {
                terror << "-p needs additional value\n";
                std::exit(EXIT_FAILURE);
            }
        }
        else if (tmp == "-w" || tmp == "--wait") {
            if (argc >= ++i +1) {
                opt.flg.wait = true;
                char *end = NULL;
                long ms = std::strtol(argv[i], &end, 10);

                if ( *end != '\0' || ms < 0 || errno != 0) {
                    terror << "Invalid wait time\n";
                    return true;
                }

                opt.val.rttMs = ms;
                opt.val.rttTmval.tv_sec = (unsigned)(this->timeout / 1000);
                opt.val.rttTmval.tv_usec = (this->timeout % 1000) * 1000;
            } else {

                terror << "-w needs additional value\n";
                return true;
            }
        }

        else {
            terror << "Invalid argument [" << tmp << "]\n";
            return true;
        }
    }

    this->opt = opt;

    return false;
}

bool Isamon::getIfaceInfo( void )
{
    errno = 0;

	debug << "Looking for avaliable ifaces ...\n";

	// ~~~ Ziskej jmena vsechny iface - preskoc "lo"
	struct ifaddrs *addrs, *tmp;
	iface_t iface;
	getifaddrs(&addrs);
	tmp = addrs;
	while ( tmp ) {
	    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
			debug << "Found iface " << tmp->ifa_name << "\n";
			if ( strcmp(tmp->ifa_name, "lo") == 0) {
				debug << "Skipping ...\n";
			}
			else {
				memset(&iface, 0, sizeof(iface));
				strncpy(iface.name, tmp->ifa_name, MAX_IFACE_NAME_BYTES);
				this->ifaces.push_back(iface);
			}
		}

	    tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);
    assert(errno == 0);


    return false;
}

bool Isamon::checkIfaceName( void )
{
    errno = 0;

    if ( this->opt.flg.iface ) {
        debug << "Checking given iface name ...\n";
        // Byla nastavena vlajka, zjisti, zda iface existuje
        for (auto it = begin(this->ifaces); it != end(this->ifaces); ) {
            if ( strncmp(i->name, this->opt.val.iface, MAX_IFACE_NAME_BYTES) != 0) {
                it = this->ifaces.erase(i);
            }
            else {
                ++i;
            }
        }
    }

    if ( this->ifaces.size() == 0) {
        return true;
    }

    assert(errno == 0);
    return false;
}

bool Isamon::Init( const int argc, const char ** argv )
{
    // ~~~ Zpracuj argumenty
    if (parseArgs(argc, argv)) {
        terror << "Argument parse error\n";
        return true;
    }

    // ~~~ Najdi informace o sitovych rozhranich
    if (getIfaceStats()) {
        terror << "Cannot get stats for ifaces\n";
        return true;
    }

    // ~~~ Over ziskane informace proti argumentum
    // Byla zadana iface, over zda existuje
    if (this->checkIfaceName()) {
		terror << "Interface " << this->opt.val.iface << " does not exists or there are no avaliable ifaces\n";
    }

    return false
}

bool Isamon::Start( void )
{
    errno = 0;
    debug << "Starting isamon scanner ...\n";

    // ~~~ Postupne oskenuj vsechny subnety
	for (auto it = begin(this->ifaces); it != end(this->ifaces); it++) {
        Scanner scanner;
        // Nastav skenner pro skenovani site na dane iface
		if (scanner.Init(*it)) {
			terror << "Cannot initialize Scanner for subnet on "<<it->name<<"\n";
			continue;
		}
		if (scanner.Start()) {
			terror << "Error while scanning subnet on " it->name << "\n";
		}
	}

    return false;
}

// <<< Tridni funkce <<<
