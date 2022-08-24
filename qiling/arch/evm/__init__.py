import sys

# python 3.10 has not been supported yet in the latest blake2b-py release
if sys.version_info >= (3,10):
    sys.exit('Sorry, Python > 3.10 is not supported for now')

#  Ensure we can reach 1024 frames of recursion
#
EVM_RECURSION_LIMIT = 1024 * 12
sys.setrecursionlimit(max(EVM_RECURSION_LIMIT, sys.getrecursionlimit()))
