from ..utils import init_struct

## NOTE TO SELF:
## functions prototypes:
## 	search:		(\w+)\s+\(EFIAPI \*(\w+)\)\s*\(\s*
## 	replace:	$2 = FUNCPTR($1, 
##
## parameters
##	search:		,\s*(\w+)\s+\w+
##	replace:	, $1
##
## pointers
## 	search:		(\w+)\s*\*\w+
## 	replace:	PTR($1)
##
## double pointers
##	search:		(\w+)\s*\*\*\w+
##	replace:	PTR(PTR($1))

def install_protocol(ql, base, descriptor, handles):
	guid = descriptor['guid']

	assert guid not in handles, f'protocol already installed ({guid})'

	# if base was specified as None, it was not pre-allocated
	if base is None:
		struct_class = descriptor['struct']
		base = ql.os.heap.alloc(struct_class.sizeof())

	handles[guid] = base

	instance = init_struct(ql, base, descriptor)
	return instance.saveTo(ql, base)

__all__ = ['install_protocol']