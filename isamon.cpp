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
 * @file    : isamon.cpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Isamon object file
 */
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>


#include "global.hpp"
#include "isamon.hpp"


// >>> Lokalni staticke funkce >>>

/// Zobraz napovedu
static void showHelp( void )
{
    using namespace std;

    cout << endl;
    cout << " USAGE: ./isamon [switches] -n <netaddr/mask>" << endl;
    cout << endl;
    cout << " -t                             : Use TCP protocol" << endl;
    cout << " -u                             : Use UDP protocol" << endl;
    cout << " -n, --network <netaddr/mask>   : Scan this network" << endl;
    cout << " -i, --interface <iface>        : NIC used for scan" << endl;
    cout << " -w, --wait <ms>                : Wait time for port response" << endl;
    cout << " -h, --help                     : Show this help screen" << endl;
    cout << endl;
    cout << " Example: ./isamon -i eth0 -t -p 22 -n 10.0.0.0/24" << endl;
    cout << endl;
}

// Najde NIC IP, NET IP, NET mask, ...
static bool getIfaceStats( iface_t * iface, const char * name )
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
    debug << "[" << name << "] Net mask\n";
    if ( ioctl( sock, SIOCGIFNETMASK, &ifr ) < 0 ) goto ERR_IOCTL;
    iface->nicMaskInAddr = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr;

    // ~~~ Najdi adresu site
    debug << "[" << name << "] Net addr\n";
    iface->nicNetInAddr.s_addr = iface->nicInAddr.s_addr &  iface->nicMaskInAddr.s_addr;

    close(sock);
    return false;

    ERR_IOCTL:
    close(sock);
    ERR_SOCK:
    return true;
}

// <<< Lokalni staticke funkce <<<
// >>> Tridni funkce >>>

bool Isamon::parseArgs( const int argc, const char ** argv )
{
    opt_t opt;
    memset(&opt, false, sizeof(opt_t));

    // Defaultni nastaveni (1s timeout)
	opt.val.rtt = 1000;
    opt.val.rttTmval.tv_sec = 1;
    opt.val.rttTmval.tv_usec = 0;

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
            std::exit(EXIT_SUCCESS);
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
                    return true;
                }

                opt.val.net.oct[0] = val[0];
                opt.val.net.oct[1] = val[1];
                opt.val.net.oct[2] = val[2];
                opt.val.net.oct[3] = val[3];
                if (val[4] < 1 || val[4] > 31) {
                    terror << "Mask must be between 1-31\n";
                    return true;
                }
                uint32_t m = 0xFFFFFFFF << (32 - val[4]);
                opt.val.mask = {
                    (uint8_t)(0xFF & (m >> 24)),
                    (uint8_t)(0xFF & (m >> 16)),
                    (uint8_t)(0xFF & (m >> 8)),
                    (uint8_t)(0xFF & m),
                };
            } else {
                terror << "-n needs additional value\n";
                return true;
            }
        }
        else if (tmp == "-i" || tmp == "--interface") {
            if (argc >= ++i +1) {
                opt.flg.iface = true;
                opt.val.iface = (char *) argv[i];
                if (strlen(opt.val.iface) > MAX_IFACE_NAME_BYTES) {
                    terror << "Iface name too long, maximum is " << MAX_IFACE_NAME_BYTES << " chars\n";
                    return true;
                }
            } else {
                terror << "-i needs additional value\n";
                return true;
            }
        }
        else if (tmp == "-p" || tmp == "--port") {
            if (argc >= ++i +1) {
                opt.flg.port = true;
                char *end = NULL;
                long port = std::strtol(argv[i], &end, 10);

                if ( *end != '\0' || port < 1 || port > 65535 || errno != 0) {
                    terror << "Invalid port number\n";
                    return true;
                }

                opt.val.port = port;
            } else {
                terror << "-p needs additional value\n";
                return true;
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
                opt.val.rtt = ms;
                opt.val.rttTmval.tv_sec = (unsigned)(ms / 1000);
                opt.val.rttTmval.tv_usec = (ms % 1000) * 1000;
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

	// ~~~ Ziskej jmena vsechny iface
	struct ifaddrs *addrs, *tmp;
	iface_t iface;
	getifaddrs(&addrs);
	tmp = addrs;
	while ( tmp ) {
	    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
			debug << "Found iface " << tmp->ifa_name << "\n";
			// if ( strcmp(tmp->ifa_name, "lo") == 0) {
			// 	debug << "Skipping ...\n";
			// 	continue
			// }
			memset(&iface, 0, sizeof(iface));
			strncpy(iface.name, tmp->ifa_name, MAX_IFACE_NAME_BYTES);
            if (getIfaceStats(&iface, tmp->ifa_name)) {
                terror << "Cannot get iface stats\n";
                freeifaddrs(addrs);
                return true;
            }
			this->ifaces.push_back(iface);
		}

	    tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);

    return false;
}

bool Isamon::checkIfaceName( void )
{
    errno = 0;

    if ( this->opt.flg.iface ) {
        debug << "Checking given iface name ...\n";
        // Byla nastavena vlajka, zjisti, zda iface existuje
        for (auto it = begin(this->ifaces); it != end(this->ifaces); ) {
            if ( strncmp(it->name, this->opt.val.iface, MAX_IFACE_NAME_BYTES) != 0) {
                it = this->ifaces.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    if ( this->ifaces.size() == 0) {
        return true;
    }

    return false;
}

bool Isamon::argCheck( void )
{
    if (this->opt.flg.help == true) {
        showHelp();
        std::exit(EXIT_SUCCESS);
    }
    if (this->opt.flg.net == false) {
        terror << "Destination network not set\n";
        std::exit(EXIT_FAILURE);
    }
    if (opt.val.rtt < 1) {
        terror << "Minimal RTT value is 1\n";
        return true;
    }
    if (opt.flg.port) {
        if ( !(opt.flg.udp || opt.flg.tcp)) {
            terror << "Port can be used only with -t or -u switch\n";
            return true;
        }
    }
    // Kontrola rozsahu IP adresy
    ip4_t start = { 1, 0, 0 , 0};
    ip4_t stop = {239, 255, 255, 255};
    if (opt.val.net < start || opt.val.net > stop ) {
        terror << "Invalid IP address range, valid range is ["<<start<<"-"<<stop<<"]\n";
        return true;
    }
    // Kontrola zda je IP adresou sitove
    ip4_t net = opt.val.net & opt.val.mask;
    debug << "Checking IP addr "<<net << " X "<<opt.val.net<<"\n";
    if ( net != opt.val.net) {
        terror << "Given adress is not network address, expected "<<net<<"\n";
        return true;
    }

    return false;
}

bool Isamon::Init( const int argc, const char ** argv )
{
    // ~~~ Zpracuj argumenty
    if (parseArgs(argc, argv)) {
        terror << "Argument parse error\n";
        return true;
    }

    if (argCheck()) {
        terror << "Arg check failed\n";
        return true;
    }

    // ~~~ Najdi informace o sitovych rozhranich
    if (getIfaceInfo()) {
        terror << "Cannot get stats for ifaces\n";
        return true;
    }

    // ~~~ Over ziskane informace proti argumentum
    // Byla zadana iface, over zda existuje
    if (this->checkIfaceName()) {
		terror << "Interface " << this->opt.val.iface << " does not exists or there are no avaliable ifaces\n";
        return true;
    }

    return false;
}

bool Isamon::Start( void )
{
    errno = 0;
    debug << "Starting isamon scanner ...\n";

    // ~~~ Postupne oskenuj vsechny subnety
	for (auto it = begin(this->ifaces); it != end(this->ifaces); it++) {
        debug << "Skennig subnet [" << it->name << "] ...\n";
        Scanner scanner;
        // Nastav skenner pro skenovani site na dane iface
		if (scanner.Init(*it, this->opt)) {
			terror << "Cannot initialize Scanner for subnet on "<<it->name<<"\n";
			continue;
		}
		if (scanner.Start()) {
			terror << "Error while scanning subnet on "<<it->name<<"\n";
		}
	}

    return false;
}

// <<< Tridni funkce <<<
