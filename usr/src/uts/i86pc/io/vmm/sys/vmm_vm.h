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

struct vmspace;
struct vm_object;
struct vm_page;
struct vm_client;

typedef struct vmspace vmspace_t;
typedef struct vm_client vm_client_t;
typedef struct vm_page vm_page_t;
typedef struct vm_object vm_object_t;

struct vm;
int vm_segmap_obj(struct vm *, int, off_t, off_t, struct as *, caddr_t *,
    uint_t, uint_t, uint_t);
int vm_segmap_space(struct vm *, off_t, struct as *, caddr_t *, off_t, uint_t,
    uint_t, uint_t);

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

/* vmspace_t operations */
struct vmspace *vmspace_alloc(size_t, struct vmm_pt_ops *);
void vmspace_destroy(struct vmspace *);
int vmspace_map(struct vmspace *, vm_object_t *, uintptr_t, uintptr_t, size_t,
    uint8_t);
int vmspace_unmap(struct vmspace *, uintptr_t, uintptr_t);
int vmspace_populate(struct vmspace *, uintptr_t, uintptr_t);
vm_client_t *vmspace_client_alloc(vmspace_t *);
uint64_t vmspace_table_root(vmspace_t *);
uint64_t vmspace_table_gen(vmspace_t *);
uint64_t vmspace_resident_count(struct vmspace *);

/* vm_client_t operations */
vm_page_t *vmc_hold(vm_client_t *, uintptr_t, int);
uint64_t vmc_table_enter(vm_client_t *);
void vmc_table_exit(vm_client_t *);
int vmc_fault(vm_client_t *, uintptr_t, int);
vm_client_t *vmc_clone(vm_client_t *);
void vmc_destroy(vm_client_t *);

/* vm_object_t operations */
vm_object_t *vm_object_mem_allocate(size_t, bool);
void vm_object_reference(vm_object_t *);
void vm_object_release(vm_object_t *);
pfn_t vm_object_pfn(vm_object_t *, uintptr_t);
struct vm_object *vmm_mmio_alloc(struct vmspace *, uintptr_t, size_t,
    uintptr_t);

/* vm_page_t operations */
const void *vmp_get_readable(const vm_page_t *);
void *vmp_get_writable(const vm_page_t *);
pfn_t vmp_get_pfn(const vm_page_t *);
vm_page_t *vmp_chain(vm_page_t *, vm_page_t *);
vm_page_t *vmp_next(const vm_page_t *);
void vmp_release(vm_page_t *);

#endif /* _VMM_VM_H */
