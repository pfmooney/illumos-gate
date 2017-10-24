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

/*
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/vmsystm.h>
#include <vm/as.h>
#include <vm/seg_vn.h>

#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include "vm/vm_glue.h"

#define	PMAP_TO_VMSPACE(pm)	((struct vmspace *)		\
	((caddr_t)(pm) - offsetof(struct vmspace, vms_pmap)))
#define	VMMAP_TO_VMSPACE(vmmap)	((struct vmspace *)		\
	((caddr_t)(vmmap) - offsetof(struct vmspace, vm_map)))

static void pmap_free(pmap_t);

struct vmspace_mapping {
	list_node_t	vmsm_node;
	vm_object_t	vmsm_object;
	caddr_t		vmsm_addr;
	size_t		vmsm_len;
};

struct vmspace *
vmspace_alloc(vm_offset_t start, vm_offset_t end, pmap_pinit_t pinit)
{
	struct vmspace *vms;
	struct as *as;

	/*
	 * This whole mess is built on the assumption that a 64-bit address
	 * space is available to work with for the various pagetable tricks.
	 */
	VERIFY(ttoproc(curthread)->p_model == DATAMODEL_LP64);
	VERIFY(start == 0 && end <= USERLIMIT);

	vms = kmem_zalloc(sizeof (*vms), KM_SLEEP);
	vms->vms_size = end;
	list_create(&vms->vms_maplist, sizeof (struct vmspace_mapping),
	    offsetof(struct vmspace_mapping, vmsm_node));

	if (pinit(&vms->vms_pmap) == 0) {
		kmem_free(vms, sizeof (*vms));
		return (NULL);
	}

	as = as_alloc();
	as->a_userlimit = (caddr_t)end;

	/* For now, lock all new mappings into the AS automatically */
	VERIFY0(as_ctl(as, NULL, 0, MC_LOCKAS, 0, MCL_FUTURE, NULL, 0));

	vms->vms_as = as;
	return (vms);
}

void
vmspace_free(struct vmspace *vms)
{
	struct as *as = vms->vms_as;

	VERIFY(list_is_empty(&vms->vms_maplist));
	VERIFY0(avl_numnodes(&as->a_segtree));

	as_free(as);
	pmap_free(&vms->vms_pmap);
	kmem_free(vms, sizeof (*vms));
}

pmap_t
vmspace_pmap(struct vmspace *vms)
{
	return (&vms->vms_pmap);
}

long
vmspace_resident_count(struct vmspace *vms)
{
	/* XXXJOY: finish */
	return (0);
}


static void
pmap_free(pmap_t pmap)
{
	kmem_free(pmap->pm_pml4,PAGESIZE);
}

int
pmap_pinit_type(pmap_t pmap, enum pmap_type type, int flags)
{
#if notyet
	struct vmspace *vms = PMAP_TO_VMSPACE(pmap);
#endif

	/* For use in vmm only */
	pmap->pm_type = type;
	switch (type) {
	case PT_EPT:
		pmap->pm_pml4 = kmem_zalloc(PAGESIZE, KM_SLEEP);
		break;
	case PT_RVI:
		/* RVI support not yet implemented */
		return (0);
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}

	/* XXXJOY: finish */
	return (1);
}

long
pmap_wired_count(pmap_t pmap)
{
	/* XXXJOY: finish */
	return (0L);
}

int
pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype)
{
	/* XXXJOY: finish */
	return (0L);
}

vm_object_t
vm_object_allocate(objtype_t type, vm_pindex_t psize)
{
	vm_object_t vmo;
	const size_t size = ptob((size_t)psize);

	/* only support anon for now */
	VERIFY(type == OBJT_DEFAULT);

	vmo = kmem_alloc(sizeof (*vmo), KM_SLEEP);
	mutex_init(&vmo->vmo_lock, NULL, MUTEX_DEFAULT, NULL);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = type;
	vmo->vmo_size = size;

	vmo->vmo_refcnt = 0;
	vmo->vmo_amp = anonmap_alloc(size, 0, ANON_SLEEP);
	/* XXXJOY: opt-in to larger pages? */

	return (vmo);
}

void
vm_object_deallocate(vm_object_t vmo)
{
	struct anon_map *amp = vmo->vmo_amp;

	/* only support anon for now */
	VERIFY(vmo->vmo_type == OBJT_DEFAULT);

	/* By the time this is deallocated, its mappings should be gone. */
	VERIFY(vmo->vmo_refcnt == 0);

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	VERIFY(amp->refcnt == 1);
	amp->refcnt = 0;

	/* Release anon memory */
	anonmap_purge(amp);
	if (amp->a_szc != 0) {
		anon_shmap_free_pages(amp, 0, amp->size);
	} else {
		anon_free(amp->ahp, 0, amp->size);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);

	anonmap_free(amp);
	kmem_free(vmo, sizeof (*vmo));
}

void
vm_object_reference(vm_object_t vmo)
{
	ASSERT(vmo != NULL);

	mutex_enter(&vmo->vmo_lock);
	vmo->vmo_refcnt++;
	mutex_exit(&vmo->vmo_lock);
}

static void
vm_object_release(vm_object_t vmo)
{
	ASSERT(vmo != NULL);

	mutex_enter(&vmo->vmo_lock);
	VERIFY(vmo->vmo_refcnt);
	vmo->vmo_refcnt--;
	mutex_exit(&vmo->vmo_lock);
}

int
vm_fault(vm_map_t map, vm_offset_t off, vm_prot_t type, int flag)
{
	/* XXXJOY: finish */
	return (0);
}

int
vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	struct as *as = vms->vms_as;
	const caddr_t vaddr = (caddr_t)addr;
	pfn_t pfn;
	uint_t pprot;
	page_t *pp = NULL;

	ASSERT(len == PAGESIZE);
	ASSERT(max_count == 1);

	mutex_enter(&vms->vms_lock);
	/* Must be within the bounds of the vmspace */
	if (addr >= vms->vms_size) {
		mutex_exit(&vms->vms_lock);
		return (-1);
	}

	AS_LOCK_ENTER(as, RW_READER);
	pfn = hat_getpfnum(as->a_hat, vaddr);
	if (pf_is_memory(pfn) && hat_getattr(as->a_hat, vaddr, &pprot) == 0) {
		/* The page is expected to be share-locked already */
		pp = page_numtopp_nolock(pfn);
		if (pp == NULL || (prot & ~pprot) == 0 ||
		    page_lock(pp, SE_SHARED, (kmutex_t *)NULL,
		    P_RECLAIM) == 0) {
			pp = NULL;
		}
	}
	AS_LOCK_EXIT(as);
	mutex_exit(&vms->vms_lock);

	if (pp != NULL) {
		*ma = (vm_page_t)pp;
		return (0);
	}
	return (-1);
}


/*
 * Find a suitable location for a mapping (and install it).
 */
int
vm_map_find(vm_map_t map, vm_object_t vmo, vm_ooffset_t off, vm_offset_t *addr,
    vm_size_t len, vm_offset_t max_addr, int find_flags, vm_prot_t prot,
    vm_prot_t prot_max, int cow)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	struct as *as = vms->vms_as;
#if notyet
	const size_t slen = (size_t)len;
#endif
	caddr_t base = (caddr_t)*addr;
	size_t maxlen;
	struct segvn_crargs svna;
	struct vmspace_mapping *vmsm;
	int res;

	/* For use in vmm only */
	VERIFY(find_flags == VMFS_NO_SPACE); /* essentially MAP_FIXED */
	VERIFY(vmo->vmo_type == OBJT_DEFAULT); /* only anon for now */

	if (len == 0 || off >= (off + len) || vmo->vmo_size < (off + len)) {
		return (EINVAL);
	}

	maxlen = (max_addr != 0) ? max_addr : vms->vms_size;
	if (*addr >= maxlen) {
		return (ENOMEM);
	} else {
		maxlen -= *addr;
	}

	vmsm = kmem_alloc(sizeof (*vmsm), KM_SLEEP);

	mutex_enter(&vms->vms_lock);
	as_rangelock(as);
	if (as_gap(as, len, &base, &maxlen, AH_LO, NULL) != 0) {
		res = ENOMEM;
		goto out;
	}

	/* XXX: verify offset/len fits in object */

	svna.vp = NULL;
	svna.offset = 0;
	svna.type = MAP_SHARED;
	svna.prot = (prot & VM_PROT_ALL) | PROT_USER;
	svna.maxprot = (prot_max & VM_PROT_ALL) | PROT_USER;
	svna.flags = MAP_ANON;
	svna.cred = CRED(); /* XXXJOY: really? */
	svna.amp = vmo->vmo_amp;
	svna.szc = 0;
	svna.lgrp_mem_policy_flags = 0;

	res = as_map(as, base, len, segvn_create, &svna);

	if (res == 0) {
		vmsm->vmsm_object = vmo;
		vmsm->vmsm_addr = base;
		vmsm->vmsm_len = len;
		list_insert_tail(&vms->vms_maplist, vmsm);

		/* Communicate out the chosen address. */
		*addr = (vm_offset_t)base;
	}
out:
	as_rangeunlock(as);
	mutex_exit(&vms->vms_lock);
	if (res != 0) {
		kmem_free(vmsm, sizeof (*vmsm));
	}
	return (res);
}

int
vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const caddr_t addr = (caddr_t)start;
	const size_t size = (size_t)(end - start);
	list_t *ml = &vms->vms_maplist;
	struct vmspace_mapping *vmsm;
	int res;

	ASSERT(start < end);

	mutex_enter(&vms->vms_lock);
	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		if (vmsm->vmsm_addr == addr && vmsm->vmsm_len == size) {
			break;
		}
	}
	if (vmsm == NULL) {
		mutex_exit(&vms->vms_lock);
		return (ENOENT);
	}
	/* XXXJOY: tear down EPT mappings too */
	res = as_unmap(vms->vms_as, addr, size);
	if (res == 0) {
		list_remove(ml, vmsm);
		vm_object_release(vmsm->vmsm_object);
		kmem_free(vmsm, sizeof (*vmsm));
	}
	mutex_exit(&vms->vms_lock);
	return (0);
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	/* XXXJOY: finish */
	return (0);
}


void
vm_page_lock(vm_page_t vmp)
{
	/*EMPTY*/
}

void
vm_page_unlock(vm_page_t vmp)
{
	/*EMPTY*/
}

void
vm_page_unhold(vm_page_t vmp)
{
	page_t *pp = (page_t *)vmp;

	ASSERT(PAGE_SHARED(pp));

	page_unlock(pp);
}
