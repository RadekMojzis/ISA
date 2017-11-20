

#ifndef LOCKOBJ_HPP_
#define LOCKOBJ_HPP_

class LockObj {
public:

	static void Lock( bool & lock );
	static void Unlock( bool & lock );

	static bool IsActive( bool lock );
	static void WaitOnLock( bool lock );

};

#endif	/* LOCKOBJ_HPP_ */
