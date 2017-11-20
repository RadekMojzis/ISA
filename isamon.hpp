


#ifndef ISAMON_HPP_
#define ISAMON_HPP_

#include <vector>

#include "globals.h"
#include "scanner.hpp"
#include "sniffer.hpp"

/// Zakladni trida popisujici cely isamon
class Isamon {
public:
	Isamon( void );
	/**
	 * Funkce inicializuje isamon, zpracuje argumenty
	 * inicializuje promenne v sekci "protected"
	 * @param  argc pocet argumentu
	 * @param  argv pole argumentu
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool Init( const int argc, const char * argv );

	/**
	 * Spusti skenovani site
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool Start( void );

protected:
	/// Sitova rozhrani detekovana isamonem
	std::vector<iface_t> ifaces;
	/// Nastaveni isamonu
	opt_t opt;

private:
	/**
	 * Funkce zpracuje argumenty a naplni strukturu opt_t
	 * @param  argc pocet argumentu
	 * @param  argv pole argumentu
	 * @return      FALSE pokud vse ok, jinak TRUE
	 */
	bool parseArgs( const int argc, const char ** argv );

	/**
	 * Ziska informace o pripojenych sitovych kartach
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool getIfaceInfo( void );

	/**
	 * Over ze zadana NIC pomoci parametru -i existuje
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool checkIfaceName( void );
};

#endif	/* ISAMON_HPP_ */
