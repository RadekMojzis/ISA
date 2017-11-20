/**
 * @file    : isamon.cpp
 * @author  : Martin Pumr
 * @date    : 2017-09-24
 *
 * @brief   Main file for ISA project
 *
 * Copyright (c) 2017 Martin Pumr All Rights Reserved.
 */

#include <iostream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <chrono>
#include <string.h>

// >>> Knihovny projektu >>>

#include "global.hpp"
#include "scanner.hpp"

// <<< Knihovny projektu <<<

// --------------------------------------------------------
// 					>>> MAIN CODE >>>
// --------------------------------------------------------
int main( int argc, const char **argv )
{
    Isamon isamon;

    // ~~~ Inicializace skenneru
    if (isamon.Init()) {
        terror << "Cannot initialize Isamon\n";
        return 1;
    }

    // ~~~ Spusteni skeneru
    if (isamon.Start()) {
        terror << "Isamon runtime error occured\n"
        return 1;
    }

    return 0;
}
// --------------------------------------------------------
// 					<<< MAIN CODE <<<
// --------------------------------------------------------
