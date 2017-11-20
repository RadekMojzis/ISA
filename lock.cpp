
#include "unistd.h"

#include "lock.hpp"

bool LockObj::IsActive( bool lock )
{
	return lock;
}

void LockObj::Lock( bool & lock )
{
	lock = true;
}

void LockObj::Unlock( bool & lock )
{
	lock = false;
}

void LockObj::WaitOnLock( bool lock )
{
	while ( LockObj::IsActive(lock) ) {
		// Ptej se jednou za X mikrosekund na vysledek
		usleep( 250 );
	}
}
