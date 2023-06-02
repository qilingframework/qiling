/* Build Instructions:
  git clone git@github.com:heroims/obfuscator.git -b llvm-9.0
  mkdir build-ollvm && cd build-ollvm
  cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF -G Ninja ../obfuscator/
  ninja
  ./bin/clang -m32 -mllvm -fla fla_test.c -o test_fla_argv
 */
#include <stdio.h>
#include <stdlib.h>

unsigned int target_function(unsigned int n)
{
  unsigned int mod = n % 4;
  unsigned int result = 0;

  if (mod == 0) result = (n | 0xBAAAD0BF) * (2 ^ n);

  else if (mod == 1) result = (n & 0xBAAAD0BF) * (3 + n);

  else if (mod == 2) result = (n ^ 0xBAAAD0BF) * (4 | n);

  else result = (n + 0xBAAAD0BF) * (5 & n);

  return result;
}

int main(int argc, char **argv) {
   int n;
   if (argc < 2) {
      n = 0;
   } else {
      n = atoi(argv[1]);
   }
   int val = target_function(n);
   printf("%d\n", val);
   return 0;
}
