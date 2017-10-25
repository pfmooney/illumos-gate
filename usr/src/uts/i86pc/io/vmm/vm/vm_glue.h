#ifndef	_VM_GLUE_
#define	_VM_GLUE_

#include <vm/pmap.h>
#include <vm/vm.h>
#include <sys/cpuvar.h>

struct vmspace;
struct vm_map;
struct pmap;

struct vm_map {
	struct vmspace *vmm_space;
};

struct pmap {
	void		*pm_pml4;
	cpuset_t	pm_active;
	long		pm_eptgen;

	/* Implementation private */
	enum pmap_type	pm_type;
};


struct vmspace {
	struct vm_map vm_map;

	/* Implementation private */
	kmutex_t	vms_lock;
	struct pmap	vms_pmap;
	struct as	*vms_as;
	uintptr_t	vms_size;	/* fixed after creation */

	list_t		vms_maplist;
};

struct vm_object {
	kmutex_t	vmo_lock;
	uint_t		vmo_refcnt;
	objtype_t	vmo_type;
	size_t		vmo_size;
	struct anon_map	*vmo_amp;
};

#endif /* _VM_GLUE_ */
