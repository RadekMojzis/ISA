



#ifndef SCANNER_HPP_
#define SCANNER_HPP_

#include <vector>

#include <net/if.h>             // struct ifreq
#include <netpacket/packet.h>   // struct sockaddr_ll

#include "global.hpp"

class Scanner {

public:
	Scanner( void );

	/**
	 * Inicializuje skener pro dané síťové rozhraní
	 * @param  iface Skenování bude probíhat na tomto rozhraní
	 * @return	FALSE pokud vse ok, jinak TRUE
	 */
	bool Init( const iface_t iface );

	/**
	 * Spust skenner a postupne oskenuj vsechny subnety
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool Start( void );

	/**
	 * Je aktualne skenovana IP adresa lokalni adresou?
	 * pokud ano, pouzij navic ARP dotaz
	 * @param  ip Dotazovana IP
	 * @return    TRUE pokud je lokalni, jinak FALSE
	 */
	bool IsIpLocal( const ip4_t ip );

private:
	/// NIC na ktere aktualne probiha sken
	iface_t currNic;
	/// Prvni a posledni skenovana IP
	ip4_t netIP4First
	ip4_t netIP4Last;

	/**
	* Nastavi vse potrebne pro oskenovani subnetu
	* @return  FALSE pokud vse ok, jinak TRUE
	*/
	bool initNet( void );

	/**
	 * Oskenuj jeden subnet
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool scanNet( void );
};

class ScannerARP {

private:
	/// NIC na ktere aktualne probiha sken
	iface_t currNic;
	
	/// Popis soketu na urovni linkove vrstvy (pro ARP)
	struct sockaddr_ll sockLLDesc;

	/**
	 * Inicializuje privatni promennout sockLLDesc
	 * Potrebne pro ARP dotazy
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool setSrcIfaceLL( void );
};

#endif	/* SCANNER_HPP_ */
