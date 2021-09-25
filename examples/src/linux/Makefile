
# c compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -s

# cpp compiler and flags
CXX = g++
CXXFLAGS = -Wall -O2 -s

# preprocessor flags, common to c and cpp
CPPFLAGS = -MD

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))
DEPS = $(patsubst %.o,%.d,$(OBJS))
MISSING_DEPS = $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES = $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

TARGETS =					\
	arm_hello				\
	arm_hello_static		\
	arm_sleep_hello			\
	arm64_hello				\
 	arm64_hello_static		\
 	arm64_sleep_hello		\
	mips32el_hello			\
 	mips32el_hello_static	\
	x86_hello				\
 	x86_hello_static		\
 	x86_hello_cpp			\
	x86_hello_cpp_static	\
	x8664_hello				\
 	x8664_hello_static		\
 	x8664_hello_cpp			\
	x8664_hello_cpp_static	\
	x8664_cloexec_test		\
	patch_test.bin

.PHONY: all clean

all : $(TARGETS)

ARM_TARGETS: $(filter arm_%,$(TARGETS))
ARM64_TARGETS: $(filter arm64_%,$(TARGETS))
MIPS32EL_TARGETS: $(filter mips32el_%,$(TARGETS))
X86_TARGETS: $(filter x86_%,$(TARGETS))
X8664_TARGETS: $(filter x8664_%,$(TARGETS))

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

arm_hello: hello.c
	arm-linux-gnueabihf-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

arm_hello_static: hello.c
	arm-linux-gnueabihf-gcc $(CPPFLAGS) $(CFLAGS) -static -o $@ $<

arm_sleep_hello: sleep_hello.c
	arm-linux-gnueabihf-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

arm64_hello: hello.c
	aarch64-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

arm64_hello_static: hello.c
	aarch64-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -static -o $@ $<

arm64_sleep_hello: sleep_hello.c
	aarch64-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

# not included in default targets because requires the Android NDK to be installed.
# add <NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/ to your path
arm64_android_hello: hello.c
	aarch64-linux-android29-clang $(CPPFLAGS) $(CFLAGS) -o $@ $<

arm64_posix_syscall: posix_syscall.c
	aarch64-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

mips32el_hello: hello.c
	mipsel-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

mips32el_hello_static: hello.c
	mipsel-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -static -o $@ $<

mips32el_posix_syscall: posix_syscall.c
	mipsel-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<

x86_hello: hello.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m32 -o $@ $<

x86_hello_static: hello.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m32 -static -o $@ $<

x86_hello_cpp: hello.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -m32 -o $@ $<

x86_hello_cpp_static: hello.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -m32 -static -o $@ $<

x86_posix_syscall: posix_syscall.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m32 -o $@ $<

x86_fetch_urandom: fetch_urandom.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m32 -o $@ $<

x8664_hello: hello.c
	$(CC) $(CFLAGS) -m64 -o $@ $<

x8664_hello_static: hello.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m64 -static -o $@ $<

x8664_hello_cpp: hello.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -m64 -o $@ $<

x8664_hello_cpp_static: hello.cpp
	$(CXX) $(CXXFLAGS) -m64 -static -o $@ $<

x8664_cloexec_test: cloexec_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -m64 -o $@ $<

libpatch_test.so: patch_test.so.h patch_test.so.c
	$(CC) $(CPPFLAGS) -Wall -s -O0 -shared -fpic -o $@ patch_test.so.c

patch_test.bin: patch_test.bin.c libpatch_test.so
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -f *.d *.s *.o *.so $(TARGETS)
