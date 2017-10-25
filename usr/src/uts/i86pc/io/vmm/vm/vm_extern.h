#ifndef _VM_EXTERN_H_
#define	_VM_EXTERN_H_

#include <sys/types.h>
#include <vm/vm.h>

struct vmspace;
struct pmap;

typedef int (*pmap_pinit_t)(struct pmap *pmap);

struct vmspace *vmspace_alloc(vm_offset_t, vm_offset_t, pmap_pinit_t);
void vmspace_free(struct vmspace *);

int vm_fault(vm_map_t, vm_offset_t, vm_prot_t, int);
int vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count);


#endif /* _VM_EXTERN_H_ */
