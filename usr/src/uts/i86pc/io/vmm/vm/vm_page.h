
#ifndef	_VM_PAGE_
#define	_VM_PAGE_

void vm_page_lock(vm_page_t);
void vm_page_unhold(vm_page_t);
void vm_page_unlock(vm_page_t);

#define	VM_PAGE_TO_PHYS(page)	(mmu_ptob((uintptr_t)((page)->p_pagenum)))

#endif /* _VM_PAGE_ */
