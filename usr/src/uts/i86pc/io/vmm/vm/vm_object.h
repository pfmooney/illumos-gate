
#ifndef	_VM_OBJECT_
#define	_VM_OBJECT_

vm_object_t vm_object_allocate(objtype_t, vm_pindex_t);
void vm_object_deallocate(vm_object_t);
void vm_object_reference(vm_object_t);

#endif /* _VM_OBJECT_ */
