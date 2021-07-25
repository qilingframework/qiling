#!/usr/bin/python3

# The winsdkapi tool parses Windows SDK JSON files and emits function declarations in either C
# declaration format, or Python winsdkapi Qiling stub. The Windows SDK JSON files can be found
# at: https://github.com/ohjeongwook/windows_sdk_data.git
#
# Usage examples:
#  o Emitting function declarations of 'shlwapi' in a C declaration style:
#    ./winsdkapi.py c "windows_sdk_data/data/shlwapi.json"
#
#  o Emitting function declarations of 'winnt' in a Python Qiling stub style, with STDCALL cc:
#    ./winsdkapi.py py-stdcall "windows_sdk_data/data/winnt.json"
#
#  o Emitting function declarations from all JSON files in a C declaration style:
#    ./winsdkapi.py c windows_sdk_data/data/*.json

import argparse
import json

from typing import Callable, Iterable, Tuple, Sequence, Mapping, Final, Any, TextIO

FuncType = str
FuncName = str
FuncArgs = Sequence[Tuple[str, str]]
FuncDecl = Tuple[FuncType, FuncName, FuncArgs]

def parse_json(jfile: TextIO) -> Sequence[FuncDecl]:
	JObj = Mapping[str, Any]

	def __parse_param(arg: JObj) -> Tuple[str, str]:
		ptrlvl = 0

		while type(arg['type']) is dict and 'type' in arg['type']:
			arg = arg['type']
			ptrlvl += 1

		aname = arg.get('name', '')
		atype = arg['type']

		if arg.get('data_type') == 'Ptr':
			ptrlvl += 1

		if type(atype) is dict:
			if atype['data_type'] == 'Struct':
				atype = atype['name']

			elif atype['data_type'] == 'Enum':
				# BUG: windows_sdk_data repo doesn't specify the name of the enum
				atype = 'enum?'

			else:
				raise RuntimeError(f'unexpected data_type (atype = {atype})')

		return (aname, atype + '*' * ptrlvl)

	def __parse_args(args: Sequence[JObj]):
		upidx = 1

		for a in args:
			aname, atype = __parse_param(a)

			if not aname:
				if atype == 'void':
					assert len(args) == 1
					continue

				aname = f'unnamedParam{upidx}'
				upidx += 1

			yield (aname, atype)

	decls = json.load(jfile)

	def __parse_decls(decls: Sequence):
		for decl in decls:
			# pick up only function declarations
			if decl.get('data_type') == 'FuncDecl':
				ftype = decl['type']
				fname = decl['name']
				fargs = decl['arguments']
				# loc = 'api_locations'

				func_type = __parse_param(ftype)
				func_name = fname
				func_args = tuple(__parse_args(fargs))

				assert func_type[0] == fname, 'function name is inconsistent with its return type declaration'

				yield (func_type[1], func_name, func_args)

	if type(decls) is not list:
		return tuple()

	return tuple(__parse_decls(decls))

def dump_py(decls: Sequence[FuncDecl], cc: str) -> Iterable[str]:
	print(f'')
	print(f'from qiling import Qiling')
	print(f'from qiling.os.windows.api import *')
	print(f'from qiling.os.windows.fncc import *')
	print(f'')

	indent: Final[str] = ' ' * 4

	def __patch_name(aname: str) -> str:
		# merely a placeholder: nothing here yet
		return aname

	def __patch_type(atype: str) -> str:
		return 'POINTER' if atype.endswith('*') else atype

	for ftype, fname, fargs in decls:
		if fargs:
			names = [__patch_name(a[0]) for a in fargs]
			types = [__patch_type(a[1]) for a in fargs]

			longest = max(len(n) for n in names)

			args = ',\n'.join(f"{indent}'{n}'{' ' * (longest - len(n))} : {t}" for n, t in zip(names, types))
			args = f'\n{args}\n'
		else:
			args = ''

		decor = f'@winsdkapi(cc={cc}, params={{{args}}})'
		proto = f'def hook_{fname}(ql: Qiling, address: int, params):'
		body = f'{indent}pass'

		# TODO: specify return type (ftype) as a comment, or None for a 'void'

		yield f'{decor}\n{proto}\n{body}\n'

def dump_c(decls: Sequence[FuncDecl], cc: str) -> Iterable[str]:
	# use a dimmed color for data types
	def __dim(s: str) -> str:
		return f'\x1b[90m{s}\x1b[39m'

	for ftype, fname, fargs in decls:
		yield f'{__dim(ftype)} {fname} ({", ".join(f"{__dim(a[1])} {a[0]}" for a in fargs)});'

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('format', choices=('c', 'py-cdecl', 'py-stdcall'), help='Declarations output format')
	parser.add_argument('jfiles', metavar='jsonfile', nargs='+', help='JSON file(s) containing API prototypes')
	args = parser.parse_args()

	fmt, _, cc = args.format.partition('-')

	handler: Callable = {
		'c'  : dump_c,
		'py' : dump_py
	}[fmt]

	for filename in args.jfiles:
		with open(filename, 'r') as jfile:
			for decl in handler(parse_json(jfile), cc):
				print(decl)
