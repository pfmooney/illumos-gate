/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/malloc.h>
#include <sys/x86_archext.h>
#include <vm/as.h>
#include <vm/hat_i86.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>

#include <sys/vmm_vm.h>
#include <sys/seg_vmm.h>
#include <sys/vmm_kernel.h>
#include <sys/vmm_reservoir.h>

struct vmspace_mapping {
	list_node_t	vmsm_node;
	vm_object_t	*vmsm_object;
	uintptr_t	vmsm_addr;
	size_t		vmsm_len;
	off_t		vmsm_offset;
	uint_t		vmsm_prot;
};
typedef struct vmspace_mapping vmspace_mapping_t;

#define	VMSM_OFFSET(vmsm, addr)	(			\
	    (vmsm)->vmsm_offset +			\
	    ((addr) - (uintptr_t)(vmsm)->vmsm_addr))

enum vm_client_state {
	VCS_IDLE	= 0,
	VCS_ACTIVE	= (1 << 0),
	VCS_HOLD	= (1 << 1),
	VCS_ON_CPU	= (1 << 2),
};


struct vmspace {
	kmutex_t	vms_lock;
	bool		vms_held;
	uintptr_t	vms_size;	/* fixed after creation */

	/* (nested) page table state */
	struct vmm_pt_ops *vms_pt_ops;
	void		*vms_pt_data;
	long		vms_pt_gen;

	list_t		vms_maplist;
	list_t		vms_clients;
};

struct vm_client {
	vmspace_t	*vmc_space;
	list_node_t	vmc_node;

	kmutex_t	vmc_lock;
	kcondvar_t	vmc_cv;
	enum vm_client_state vmc_state;
	int		vmc_cpu_active;
	uint64_t	vmc_cpu_gen;

	list_t		vmc_held_pages;
};

enum vm_object_type {
	VMOT_NONE,
	VMOT_MEM,
	VMOT_MMIO,
};

struct vm_object {
	uint_t		vmo_refcnt;	/* manipulated with atomic ops */

	/* Fields below are fixed at creation time */
	enum vm_object_type vmo_type;
	size_t		vmo_size;
	void		*vmo_data;
	vm_memattr_t	vmo_attr;
};

struct vm_page {
	vm_client_t	*vmp_client;
	list_node_t	vmp_node;
	vm_page_t	*vmp_chain;
	uintptr_t	vmp_gpa;
	pfn_t		vmp_pfn;
	int		vmp_prot;
};


static vmspace_mapping_t *vm_mapping_find(struct vmspace *, uintptr_t, size_t,
    boolean_t);
static void vmc_space_hold(vm_client_t *);
static void vmc_space_release(vm_client_t *, bool);


struct vmspace *
vmspace_alloc(size_t end, struct vmm_pt_ops *ops)
{
	struct vmspace *vms;
	const uintptr_t size = end + 1;

	/*
	 * This whole mess is built on the assumption that a 64-bit address
	 * space is available to work with for the various pagetable tricks.
	 */
	VERIFY(ttoproc(curthread)->p_model == DATAMODEL_LP64);
	VERIFY(size > 0 && (size & PAGEOFFSET) == 0 &&
	    size <= (uintptr_t)USERLIMIT);

	vms = kmem_zalloc(sizeof (*vms), KM_SLEEP);
	vms->vms_size = size;
	list_create(&vms->vms_maplist, sizeof (vmspace_mapping_t),
	    offsetof(vmspace_mapping_t, vmsm_node));
	list_create(&vms->vms_clients, sizeof (vm_client_t),
	    offsetof(vm_client_t, vmc_node));

	vms->vms_pt_ops = ops;
	vms->vms_pt_data = ops->vpo_alloc();
	vms->vms_pt_gen = 1;

	return (vms);
}

void
vmspace_destroy(struct vmspace *vms)
{
	VERIFY(list_is_empty(&vms->vms_maplist));
	VERIFY(list_is_empty(&vms->vms_clients));

	vms->vms_pt_ops->vpo_free(vms->vms_pt_data);
	kmem_free(vms, sizeof (*vms));
}

uint64_t
vmspace_resident_count(struct vmspace *vms)
{
	return (vms->vms_pt_ops->vpo_wired_cnt(vms->vms_pt_data));
}

static pfn_t
vm_object_pager_reservoir(vm_object_t *vmo, uintptr_t off)
{
	vmmr_region_t *region;
	pfn_t pfn;

	ASSERT(vmo->vmo_type == VMOT_MEM);

	region = vmo->vmo_data;
	pfn = vmmr_region_pfn_at(region, off & PAGEMASK);

	return (pfn);
}

static pfn_t
vm_object_pager_mmio(vm_object_t *vmo, uintptr_t off)
{
	pfn_t pfn;

	ASSERT3U(vmo->vmo_type, ==, VMOT_MMIO);
	ASSERT3P(vmo->vmo_data, !=, NULL);
	ASSERT3U(off, < , vmo->vmo_size);

	pfn = ((uintptr_t)vmo->vmo_data + (off & PAGEMASK)) >> PAGESHIFT;

	return (pfn);
}

vm_object_t *
vm_object_mem_allocate(size_t size, bool transient)
{
	int err;
	vmmr_region_t *region = NULL;
	vm_object_t *vmo;

	ASSERT3U(size, !=, 0);
	ASSERT3U(size & PAGEOFFSET, ==, 0);

	err = vmmr_alloc(size, transient, &region);
	if (err != 0) {
		return (NULL);
	}

	vmo = kmem_alloc(sizeof (vm_object_t), KM_SLEEP);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = VMOT_MEM;
	vmo->vmo_size = size;
	vmo->vmo_attr = MTRR_TYPE_WB;
	vmo->vmo_data = region;
	vmo->vmo_refcnt = 1;

	return (vmo);
}

static vm_object_t *
vm_object_mmio_allocate(size_t size, uintptr_t hpa)
{
	vm_object_t *vmo;

	ASSERT3U(size, !=, 0);
	ASSERT3U(size & PAGEOFFSET, ==, 0);
	ASSERT3U(hpa & PAGEOFFSET, ==, 0);

	vmo = kmem_alloc(sizeof (vm_object_t), KM_SLEEP);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = VMOT_MMIO;
	vmo->vmo_size = size;
	vmo->vmo_attr = MTRR_TYPE_UC;
	vmo->vmo_data = (void *)hpa;
	vmo->vmo_refcnt = 1;

	return (vmo);
}

vm_object_t *
vmm_mmio_alloc(struct vmspace *vmspace, vm_paddr_t gpa, size_t len,
    vm_paddr_t hpa)
{
	int error;
	vm_object_t *obj;

	obj = vm_object_mmio_allocate(len, hpa);
	if (obj != NULL) {
		error = vmspace_map(vmspace, obj, 0, gpa, len,
		    PROT_READ | PROT_WRITE);
		if (error != 0) {
			vm_object_release(obj);
			obj = NULL;
		}
	}

	return (obj);
}

void
vm_object_release(vm_object_t *vmo)
{
	ASSERT(vmo != NULL);

	uint_t ref = atomic_dec_uint_nv(&vmo->vmo_refcnt);
	/* underflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, UINT_MAX);
	if (ref != 0) {
		return;
	}

	switch (vmo->vmo_type) {
	case VMOT_MEM:
		vmmr_free((vmmr_region_t *)vmo->vmo_data);
		break;
	case VMOT_MMIO:
		break;
	default:
		panic("unexpected object type %u", vmo->vmo_type);
		break;
	}

	vmo->vmo_data = NULL;
	vmo->vmo_size = 0;
	kmem_free(vmo, sizeof (*vmo));
}

void
vm_object_reference(vm_object_t *vmo)
{
	ASSERT(vmo != NULL);

	uint_t ref = atomic_inc_uint_nv(&vmo->vmo_refcnt);
	/* overflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, 0);
}

pfn_t
vm_object_pfn(vm_object_t *vmo, uintptr_t off)
{
	switch (vmo->vmo_type) {
	case VMOT_MEM:
		return (vm_object_pager_reservoir(vmo, off));
	case VMOT_MMIO:
		return (vm_object_pager_mmio(vmo, off));
	case VMOT_NONE:
	default:
		panic("unexpected object type %u", vmo->vmo_type);
		break;
	}
}

static vmspace_mapping_t *
vm_mapping_find(struct vmspace *vms, uintptr_t addr, size_t size,
    boolean_t no_lock)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size;

	ASSERT(addr <= range_end);

	if (no_lock) {
		/*
		 * This check should be superflous with the protections
		 * promised by the bhyve logic which calls into the VM shim.
		 * All the same, it is cheap to be paranoid.
		 */
		VERIFY(!vms->vms_held);
	} else {
		VERIFY(MUTEX_HELD(&vms->vms_lock));
	}

	if (addr >= vms->vms_size) {
		return (NULL);
	}
	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len;

		if (addr >= vmsm->vmsm_addr && addr < seg_end) {
			if (range_end <= seg_end) {
				return (vmsm);
			} else {
				return (NULL);
			}
		}
	}
	return (NULL);
}

static boolean_t
vm_mapping_gap(struct vmspace *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size - 1;

	ASSERT(MUTEX_HELD(&vms->vms_lock));
	ASSERT(size > 0);

	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len - 1;

		/*
		 * The two ranges do not overlap if the start of either of
		 * them is after the end of the other.
		 */
		if (vmsm->vmsm_addr > range_end || addr > seg_end)
			continue;
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
vm_mapping_remove(struct vmspace *vms, vmspace_mapping_t *vmsm)
{
	list_t *ml = &vms->vms_maplist;

	ASSERT(MUTEX_HELD(&vms->vms_lock));
	ASSERT(vms->vms_held);

	list_remove(ml, vmsm);
	vm_object_release(vmsm->vmsm_object);
	kmem_free(vmsm, sizeof (*vmsm));
}

static void
vmspace_hold_enter(vmspace_t *vms)
{
	mutex_enter(&vms->vms_lock);
	VERIFY(!vms->vms_held);

	vm_client_t *vmc = list_head(&vms->vms_clients);
	for (; vmc != NULL; vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_hold(vmc);
	}
	vms->vms_held = true;
}

static void
vmspace_hold_exit(vmspace_t *vms, bool kick_on_cpu)
{
	ASSERT(MUTEX_HELD(&vms->vms_lock));
	VERIFY(vms->vms_held);

	vm_client_t *vmc = list_head(&vms->vms_clients);
	for (; vmc != NULL; vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_release(vmc, kick_on_cpu);
	}
	vms->vms_held = false;
	mutex_exit(&vms->vms_lock);
}

int
vmspace_map(struct vmspace *vms, vm_object_t *vmo, vm_ooffset_t off,
    vm_offset_t addr, vm_size_t len, vm_prot_t prot)
{
	const size_t size = (size_t)len;
	const uintptr_t uoff = (uintptr_t)off;
	uintptr_t base = addr;
	vmspace_mapping_t *vmsm;
	int res = 0;

	if (size == 0 || off < 0 ||
	    uoff >= (uoff + size) || vmo->vmo_size < (uoff + size)) {
		return (EINVAL);
	}

	if (addr >= vms->vms_size) {
		return (ENOMEM);
	}

	vmsm = kmem_alloc(sizeof (*vmsm), KM_SLEEP);

	vmspace_hold_enter(vms);
	if (!vm_mapping_gap(vms, base, size)) {
		res = ENOMEM;
		goto out;
	}

	if (res == 0) {
		vmsm->vmsm_object = vmo;
		vmsm->vmsm_addr = base;
		vmsm->vmsm_len = len;
		vmsm->vmsm_offset = (off_t)uoff;
		vmsm->vmsm_prot = prot;
		list_insert_tail(&vms->vms_maplist, vmsm);
	}
out:
	vmspace_hold_exit(vms, false);
	if (res != 0) {
		kmem_free(vmsm, sizeof (*vmsm));
	}
	return (res);
}

int
vmspace_unmap(struct vmspace *vms, vm_offset_t start, vm_offset_t end)
{
	const uintptr_t addr = start;
	const size_t size = (size_t)(end - start);
	vmspace_mapping_t *vmsm;

	ASSERT(start < end);

	vmspace_hold_enter(vms);
	/* expect to match existing mapping exactly */
	if ((vmsm = vm_mapping_find(vms, addr, size, B_FALSE)) == NULL ||
	    vmsm->vmsm_addr != addr || vmsm->vmsm_len != size) {
		vmspace_hold_exit(vms, false);
		return (ENOENT);
	}

	(void) vms->vms_pt_ops->vpo_unmap(vms->vms_pt_data, addr, end);
	vms->vms_pt_gen++;

	vm_mapping_remove(vms, vmsm);
	vmspace_hold_exit(vms, true);
	return (0);
}

int
vmspace_populate(struct vmspace *vms, vm_offset_t start, vm_offset_t end)
{
	const uintptr_t addr = start;
	const size_t size = end - start;
	vmspace_mapping_t *vmsm;
	vm_object_t *vmo;
	uint_t prot;

	mutex_enter(&vms->vms_lock);

	/* For the time being, only exact-match mappings are expected */
	if ((vmsm = vm_mapping_find(vms, addr, size, B_FALSE)) == NULL) {
		mutex_exit(&vms->vms_lock);
		return (FC_NOMAP);
	}
	vmo = vmsm->vmsm_object;
	prot = vmsm->vmsm_prot;

	for (uintptr_t pos = addr; pos < end; ) {
		pfn_t pfn;
		uintptr_t pg_size, map_addr;
		uint_t map_lvl = 0;
		int err;

		/* XXXJOY: punt on large pages for now */
		pfn = vm_object_pfn(vmo, VMSM_OFFSET(vmsm, pos));
		pg_size = LEVEL_SIZE(map_lvl);
		map_addr = P2ALIGN(pos, pg_size);
		VERIFY(pfn != PFN_INVALID);

		err = vms->vms_pt_ops->vpo_map(vms->vms_pt_data, map_addr,
		    pfn, map_lvl, prot, vmo->vmo_attr);
		switch (err) {
		case 0:
			vms->vms_pt_gen++;
			/* FALLTHROUGH */
		case EEXIST:
			/* It is possible to race on mapping in a page */
			break;
		default:
			panic("unexpected NPT map error %d", err);
		}

		pos += pg_size;
	}

	mutex_exit(&vms->vms_lock);
	return (0);
}


vm_client_t *
vmspace_client_alloc(vmspace_t *vms)
{
	vm_client_t *vmc;

	vmc = kmem_zalloc(sizeof (vm_client_t), KM_SLEEP);
	vmc->vmc_space = vms;
	mutex_init(&vmc->vmc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vmc->vmc_cv, NULL, CV_DRIVER, NULL);
	vmc->vmc_state = VCS_IDLE;
	list_create(&vmc->vmc_held_pages, sizeof (vm_page_t),
	    offsetof(vm_page_t, vmp_node));

	mutex_enter(&vms->vms_lock);
	list_insert_tail(&vms->vms_clients, vmc);
	mutex_exit(&vms->vms_lock);

	return (vmc);
}

void
vmspace_client_destroy(vmspace_t *vms, vm_client_t *vmc)
{
	mutex_enter(&vms->vms_lock);

	mutex_enter(&vmc->vmc_lock);
	VERIFY3P(vms, ==, vmc->vmc_space);
	VERIFY(list_is_empty(&vmc->vmc_held_pages));
	VERIFY0(vmc->vmc_state & (VCS_ACTIVE | VCS_ON_CPU));
	mutex_exit(&vmc->vmc_lock);

	list_remove(&vms->vms_clients, vmc);
	mutex_exit(&vms->vms_lock);

	kmem_free(vmc, sizeof (vm_client_t));
}

uint64_t
vmspace_table_root(vmspace_t *vms)
{
	return (vms->vms_pt_ops->vpo_pmtp(vms->vms_pt_data));
}

uint64_t
vmspace_table_gen(vmspace_t *vms)
{
	return (vms->vms_pt_gen);
}

/*
 * Returns with vmc_lock held
 */
static void
vmc_activate(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY0(vmc->vmc_state & VCS_ACTIVE);
	while ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
	}
	vmc->vmc_state |= VCS_ACTIVE;
}

/*
 * Returns with vmc_lock held
 */
static void
vmc_deactivate(vm_client_t *vmc)
{
	ASSERT(MUTEX_HELD(&vmc->vmc_lock));
	VERIFY(vmc->vmc_state & VCS_ACTIVE);

	vmc->vmc_state ^= VCS_ACTIVE;
	if ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_broadcast(&vmc->vmc_cv);
	}
	mutex_exit(&vmc->vmc_lock);
}

/*
 * Indicate that a CPU will be utilizing the nested page tables through this VM
 * client.  Interrpts (and/or the GIF) are expected to be disabled when calling
 * this function.
 */
uint64_t
vmc_table_enter(vm_client_t *vmc)
{
	vmspace_t *vms = vmc->vmc_space;
	uint64_t gen;

	ASSERT0(vmc->vmc_state & (VCS_ACTIVE | VCS_ON_CPU));
	ASSERT3S(vmc->vmc_cpu_active, ==, -1);

	/*
	 * Since the NPT activation occurs with interrupts disabled, this must
	 * be done without taking vmc_lock like normal.
	 */
	gen = vms->vms_pt_gen;
	vmc->vmc_cpu_active = CPU->cpu_id;
	vmc->vmc_cpu_gen = gen;
	atomic_or_uint(&vmc->vmc_state, VCS_ON_CPU);

	return (gen);
}

/*
 * Indicate that this VM client is not longer (directly) using the underlying
 * page tables.  Interrupts (and/or the GIF) must be enabled prior to calling
 * this function.
 */
void
vmc_table_exit(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);

	ASSERT(vmc->vmc_state & VCS_ON_CPU);
	vmc->vmc_state ^= VCS_ON_CPU;
	vmc->vmc_cpu_active = -1;
	if ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_broadcast(&vmc->vmc_cv);
	}

	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_hold(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY0(vmc->vmc_state & VCS_HOLD);

	/*
	 * Because vmc_table_enter() alters vmc_state from a context where
	 * interrupts are disabled, it cannot pay heed to vmc_lock, so setting
	 * VMC_HOLD must be done atomically here.
	 */
	atomic_or_uint(&vmc->vmc_state, VCS_HOLD);

	/* Wait for client to go inactive */
	while ((vmc->vmc_state & VCS_ACTIVE) != 0) {
		cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
	}
	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_release(vm_client_t *vmc, bool kick_on_cpu)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY(vmc->vmc_state & VCS_HOLD);

	if (kick_on_cpu && (vmc->vmc_state & VCS_ON_CPU) != 0) {
		poke_cpu(vmc->vmc_cpu_active);

		while ((vmc->vmc_state & VCS_ON_CPU) != 0) {
			cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
		}
	}

	/*
	 * Because vmc_table_enter() alters vmc_state from a context where
	 * interrupts are disabled, it cannot pay heed to vmc_lock, so clearing
	 * VMC_HOLD must be done atomically here.
	 */
	atomic_and_uint(&vmc->vmc_state, ~VCS_HOLD);
	mutex_exit(&vmc->vmc_lock);
}

vm_page_t *
vmc_hold(vm_client_t *vmc, uintptr_t gpa, int prot)
{
	vmspace_t *vms = vmc->vmc_space;
	vmspace_mapping_t *vmsm;
	vm_object_t *vmo;
	vm_page_t *vmp;

	ASSERT0(gpa & PAGEOFFSET);
	ASSERT((prot & (PROT_READ | PROT_WRITE)) != PROT_NONE);

	vmp = kmem_alloc(sizeof (vm_page_t), KM_SLEEP);
	vmc_activate(vmc);

	if ((vmsm = vm_mapping_find(vms, gpa, PAGESIZE, B_TRUE)) == NULL ||
	    (prot & ~vmsm->vmsm_prot) != 0) {
		vmc_deactivate(vmc);
		kmem_free(vmp, sizeof (vm_page_t));
		return (NULL);
	}
	vmo = vmsm->vmsm_object;

	vmp->vmp_client = vmc;
	vmp->vmp_gpa = gpa;
	vmp->vmp_pfn = vm_object_pfn(vmo, VMSM_OFFSET(vmsm, gpa));
	vmp->vmp_prot = prot;
	list_insert_tail(&vmc->vmc_held_pages, vmp);
	vmc_deactivate(vmc);

	return (vmp);
}

int
vmc_fault(vm_client_t *vmc, uintptr_t gpa, int type)
{
	vmspace_t *vms = vmc->vmc_space;
	vmspace_mapping_t *vmsm;
	vm_object_t *vmo;
	uint_t prot, map_lvl;
	pfn_t pfn;
	uintptr_t map_addr;
	int err;

	vmc_activate(vmc);
	if (vms->vms_pt_ops->vpo_is_wired(vms->vms_pt_data, gpa, &prot) == 0) {
		/*
		 * It is possible that multiple vCPUs will race to fault-in a
		 * given address.  In such cases, the race loser(s) will
		 * encounter the already-mapped page, needing to do nothing
		 * more than consider it a success.
		 *
		 * If the fault exceeds protection, it is an obvious error.
		 */
		if ((prot & type) != type) {
			err = FC_PROT;
		} else {
			err = 0;
		}
		vmc_deactivate(vmc);
		return (err);
	}

	/* Try to wire up the address */
	if ((vmsm = vm_mapping_find(vms, gpa, 0, B_FALSE)) == NULL) {
		vmc_deactivate(vmc);
		return (FC_NOMAP);
	}
	vmo = vmsm->vmsm_object;
	prot = vmsm->vmsm_prot;

	/* XXXJOY: punt on large pages for now */
	pfn = vm_object_pfn(vmo, VMSM_OFFSET(vmsm, gpa));
	map_lvl = 0;
	map_addr = P2ALIGN((uintptr_t)gpa, LEVEL_SIZE(map_lvl));
	VERIFY(pfn != PFN_INVALID);

	err = vms->vms_pt_ops->vpo_map(vms->vms_pt_data, map_addr, pfn,
	    map_lvl, prot, vmo->vmo_attr);
	switch (err) {
	case 0:
		vms->vms_pt_gen++;
		/* FALLTHROUGH */
	case EEXIST:
		/* It is possible to race on mapping in a page */
		break;
	default:
		panic("unexpected NPT map error %d", err);
	}
	vmc_deactivate(vmc);

	return (0);
}


static __inline void *
vmp_ptr(const vm_page_t *vmp)
{
	ASSERT3U(vmp->vmp_pfn, !=, PFN_INVALID);

	const uintptr_t paddr = (vmp->vmp_pfn << PAGESHIFT);
	return ((void *)((uintptr_t)kpm_vbase + paddr));
}

const void *
vmp_get_readable(const vm_page_t *vmp)
{
	ASSERT(vmp->vmp_prot & PROT_READ);

	return (vmp_ptr(vmp));
}

void *
vmp_get_writable(const vm_page_t *vmp)
{
	ASSERT(vmp->vmp_prot & PROT_WRITE);
	return (vmp_ptr(vmp));
}

pfn_t
vmp_get_pfn(const vm_page_t *vmp)
{
	return (vmp->vmp_pfn);
}

vm_page_t *
vmp_chain(vm_page_t *vmp, vm_page_t *to_chain)
{
	vm_page_t *old = vmp->vmp_chain;
	vmp->vmp_chain = to_chain;
	return (old);
}

vm_page_t *
vmp_next(const vm_page_t *vmp)
{
	return (vmp->vmp_chain);
}

void
vmp_release(vm_page_t *vmp)
{
	vm_client_t *vmc = vmp->vmp_client;

	mutex_enter(&vmc->vmc_lock);
	list_remove(&vmc->vmc_held_pages, vmp);
	mutex_exit(&vmc->vmc_lock);
	/* TODO: re-dirty page if necessary */
	kmem_free(vmp, sizeof (vm_page_t));
}


int
vm_segmap_obj(struct vm *vm, int segid, off_t segoff, off_t len,
    struct as *as, caddr_t *addrp, uint_t prot, uint_t maxprot, uint_t flags)
{
	vm_object_t *vmo;
	int err;

	if (segoff < 0 || len <= 0 ||
	    (segoff & PAGEOFFSET) != 0 || (len & PAGEOFFSET) != 0) {
		return (EINVAL);
	}
	err = vm_get_memseg(vm, segid, NULL, NULL, &vmo);
	if (err != 0) {
		return (err);
	}

	VERIFY(segoff >= 0);
	VERIFY(len <= vmo->vmo_size);
	VERIFY((len + segoff) <= vmo->vmo_size);

	if (vmo->vmo_type != VMOT_MEM) {
		/* Only support memory objects for now */
		return (ENOTSUP);
	}

	as_rangelock(as);

	err = choose_addr(as, addrp, (size_t)len, 0, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;

		svma.obj = vmo;
		svma.offset = segoff;
		svma.prot = prot;

		err = as_map(as, *addrp, (size_t)len, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	return (err);
}

int
vm_segmap_space(struct vm *vm, off_t off, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags)
{

	const uintptr_t addr = (uintptr_t)off;
	const size_t size = (uintptr_t)len;
	int err;

	if (off < 0 || len <= 0 ||
	    (addr & PAGEOFFSET) != 0 || (size & PAGEOFFSET) != 0) {
		return (EINVAL);
	}

	/* TODO: actually wire this up */
	/* if ((prot & ~(vmsm->vmsm_prot | PROT_USER)) != 0) { */
	/* 	mutex_exit(&vms->vms_lock); */
	/* 	return (EACCES); */
	/* } */

	as_rangelock(as);

	err = choose_addr(as, addrp, size, off, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;

		/* svma.obj = vmo; */
		/* svma.offset = mapoff; */
		svma.prot = prot;

		err = as_map(as, *addrp, len, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	return (err);
}
