#ifndef _PMAP_VM_
#define	_PMAP_VM_

#include <machine/pmap.h>
#include "vm_glue.h"

void	pmap_invalidate_cache(void);
void	pmap_get_mapping(pmap_t pmap, vm_offset_t va, uint64_t *ptr, int *num);
int	pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype);
long	pmap_wired_count(pmap_t pmap);

#endif /* _PMAP_VM_ */
