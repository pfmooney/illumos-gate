#ifndef _COMPAT_FREEBSD_VM_VM_PARAM_H_
#define	_COMPAT_FREEBSD_VM_VM_PARAM_H_

#include <machine/vmparam.h>

#define	KERN_SUCCESS		0

/*
 * While our native userlimit is higher than this, keep it below the VA hole
 * for simplicity when dealing with EPT/NPT limits.
 */
#define	VM_MAXUSER_ADDRESS	0x000007FFFFFFFFFF

#endif	/* _COMPAT_FREEBSD_VM_VM_PARAM_H_ */
