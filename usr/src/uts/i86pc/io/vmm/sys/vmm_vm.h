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
 */

#ifndef	_VMM_VM_H
#define	_VMM_VM_H

#include <sys/list.h>
#include <sys/types.h>
#include <vm/hat_pte.h>
#include <machine/pmap.h>

/*
 * vm_fault option flags
 */
#define	VM_FAULT_NORMAL		0	/* Nothing special */
#define	VM_FAULT_WIRE		1	/* Wire the mapped page */
#define	VM_FAULT_DIRTY		2	/* Dirty the page; use w/PROT_COPY */

/*
 * The VM_MAXUSER_ADDRESS determines the upper size limit of a vmspace.
 * This value is sized well below the host userlimit, halving the
 * available space below the VA hole to avoid Intel EPT limits and
 * leave room available in the usable VA range for other mmap tricks.
 */
#define	VM_MAXUSER_ADDRESS	0x00003ffffffffffful

/*
 * Type definitions used in the hypervisor.
 */
typedef uchar_t vm_prot_t;

/* New type declarations. */
struct vmspace;
struct pmap;

struct vm_object;
typedef struct vm_object *vm_object_t;

struct vmm_pt_ops;

struct vm_page;
typedef struct vm_page *vm_page_t;

pmap_t vmspace_pmap(struct vmspace *);

int vm_map_add(struct vmspace *, vm_object_t, vm_ooffset_t, vm_offset_t,
    vm_size_t, vm_prot_t);
int vm_map_remove(struct vmspace *, vm_offset_t, vm_offset_t);
int vm_map_wire(struct vmspace *, vm_offset_t start, vm_offset_t end);

long vmspace_resident_count(struct vmspace *vmspace);

void	pmap_invalidate_cache(void);
void	pmap_get_mapping(pmap_t pmap, vm_offset_t va, uint64_t *ptr, int *num);
int	pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype);
long	pmap_wired_count(pmap_t pmap);

struct pmap {
	void		*pm_pml4;
	cpuset_t	pm_active;
	long		pm_eptgen;

	/* Implementation private */
	enum pmap_type	pm_type;
	struct vmm_pt_ops *pm_ops;
	void		*pm_impl;
};

struct vm_page {
	kmutex_t		vmp_lock;
	pfn_t			vmp_pfn;
	struct vm_object	*vmp_obj_held;
};

/* illumos-specific functions for setup and operation */
int vm_segmap_obj(vm_object_t, off_t, size_t, struct as *, caddr_t *, uint_t,
    uint_t, uint_t);
int vm_segmap_space(struct vmspace *, off_t, struct as *, caddr_t *, off_t,
    uint_t, uint_t, uint_t);
void *vmspace_find_kva(struct vmspace *, uintptr_t, size_t);

struct vmm_pt_ops {
	void * (*vpo_init)(uint64_t *);
	void (*vpo_free)(void *);
	uint64_t (*vpo_wired_cnt)(void *);
	int (*vpo_is_wired)(void *, uint64_t, uint_t *);
	int (*vpo_map)(void *, uint64_t, pfn_t, uint_t, uint_t, uint8_t);
	uint64_t (*vpo_unmap)(void *, uint64_t, uint64_t);
};

extern struct vmm_pt_ops ept_ops;
extern struct vmm_pt_ops rvi_ops;

typedef int (*pmap_pinit_t)(struct pmap *pmap);

struct vmspace *vmspace_alloc(vm_offset_t, vm_offset_t, pmap_pinit_t);
void vmspace_free(struct vmspace *);

int vm_fault(struct vmspace *, vm_offset_t, vm_prot_t, int);
int vm_fault_quick_hold_pages(struct vmspace *, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count);

vm_object_t vm_object_mem_allocate(size_t, bool);
void vm_object_deallocate(vm_object_t);
void vm_object_reference(vm_object_t);
pfn_t vm_object_pfn(vm_object_t, uintptr_t);
struct vm_object *vmm_mmio_alloc(struct vmspace *, vm_paddr_t gpa, size_t len,
    vm_paddr_t hpa);

void vm_page_unwire(vm_page_t);

#define	VM_PAGE_TO_PHYS(page)	(mmu_ptob((uintptr_t)((page)->vmp_pfn)))

#endif /* _VMM_VM_H */
