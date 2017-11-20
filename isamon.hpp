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
 * @brief   Isamon object header file
 */


#ifndef ISAMON_HPP_
#define ISAMON_HPP_

#include <vector>

#include "global.hpp"
#include "scanner.hpp"
#include "sniffer.hpp"

/// Zakladni trida popisujici cely isamon
class Isamon {
public:
	/**
	 * Funkce inicializuje isamon, zpracuje argumenty
	 * inicializuje promenne v sekci "protected"
	 * @param  argc pocet argumentu
	 * @param  argv pole argumentu
	 * @return  FALSE pokud vse ok, jinak TRUE
	 */
	bool Init( const int argc, const char ** argv );

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
	 * Zkontroluje argumenty (rozsahy, hodnoty, atd.)
	 * @return      FALSE pokud vse ok, jinak TRUE
	 */
	bool argCheck( void );

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
