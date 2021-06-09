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

/*
 * The VM_MAXUSER_ADDRESS determines the upper size limit of a vmspace.
 * This value is sized well below the host userlimit, halving the
 * available space below the VA hole to avoid Intel EPT limits and
 * leave room available in the usable VA range for other mmap tricks.
 */
#define	VM_MAXUSER_ADDRESS	0x00003ffffffffffful

/* Glue functions */

vm_paddr_t vtophys(void *);
void invalidate_cache_all(void);

/*
 * Type definitions used in the hypervisor.
 */
typedef uchar_t vm_prot_t;

/* New type declarations. */
struct vmspace;
struct vm_object;
struct vm_page;

typedef struct vm_object *vm_object_t;
typedef struct vm_page *vm_page_t;

struct vmm_pt_ops;

int vm_map_add(struct vmspace *, vm_object_t, vm_ooffset_t, vm_offset_t,
    vm_size_t, vm_prot_t);
int vm_map_remove(struct vmspace *, vm_offset_t, vm_offset_t);
int vm_map_wire(struct vmspace *, vm_offset_t start, vm_offset_t end);

long vmspace_resident_count(struct vmspace *vmspace);


void vmspace_get_mapping(struct vmspace *, vm_offset_t, uint64_t *, int *);
int vmspace_emulate_accessed_dirty(struct vmspace *, vm_offset_t, int);
long vmspace_wired_count(struct vmspace *);

/* illumos-specific functions for setup and operation */
int vm_segmap_obj(vm_object_t, off_t, size_t, struct as *, caddr_t *, uint_t,
    uint_t, uint_t);
int vm_segmap_space(struct vmspace *, off_t, struct as *, caddr_t *, off_t,
    uint_t, uint_t, uint_t);
void *vmspace_find_kva(struct vmspace *, uintptr_t, size_t);

struct vmm_pt_ops {
	int (*vpo_init)();
	void * (*vpo_alloc)();
	void (*vpo_free)(void *);
	uint64_t (*vpo_pmtp)(void *);
	uint64_t (*vpo_wired_cnt)(void *);
	int (*vpo_is_wired)(void *, uint64_t, uint_t *);
	int (*vpo_map)(void *, uint64_t, pfn_t, uint_t, uint_t, uint8_t);
	uint64_t (*vpo_unmap)(void *, uint64_t, uint64_t);
};

extern struct vmm_pt_ops ept_ops;
extern struct vmm_pt_ops rvi_ops;

struct vmspace *vmspace_alloc(size_t, struct vmm_pt_ops *);
void vmspace_free(struct vmspace *);
uint64_t vmspace_pmtp(struct vmspace *);
uint64_t vmspace_pmtgen(struct vmspace *);

int vm_fault(struct vmspace *, vm_offset_t, vm_prot_t);
int vm_fault_quick_hold_pages(struct vmspace *, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count);

vm_object_t vm_object_mem_allocate(size_t, bool);
void vm_object_deallocate(vm_object_t);
void vm_object_reference(vm_object_t);
pfn_t vm_object_pfn(vm_object_t, uintptr_t);
struct vm_object *vmm_mmio_alloc(struct vmspace *, vm_paddr_t gpa, size_t len,
    vm_paddr_t hpa);

void *vm_page_ptr(vm_page_t);
void vm_page_release(vm_page_t);

#endif /* _VMM_VM_H */
