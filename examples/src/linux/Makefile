CC = gcc

CFLAGS = -Wall -O2 -s

#CFLAGS += -DDEBUG

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

DEPS = $(patsubst %.o,%.d,$(OBJS))
CFLAGS += -MD
MISSING_DEPS = $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES = $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

LIBS=

TARGET = arm_hello arm_hello_static \
            arm64_hello arm64_hello_static \
            mips32el_hello mips32el_hello_static \
            x86_hello x86_hello_static \
            x8664_hello x8664_hello_static

all : $(TARGET)

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

arm_hello: hello.c
	arm-linux-gnueabihf-gcc -Wall -O2 -s $< -o $@

arm_hello_static: hello.c
	arm-linux-gnueabihf-gcc -Wall -O2 -s -static $< -o $@

arm64_hello: hello.c
	aarch64-linux-gnu-gcc -Wall -O2 -s $< -o $@

arm64_hello_static: hello.c
	aarch64-linux-gnu-gcc -Wall -O2 -s -static $< -o $@

# not included in default targets because requires the Android NDK to be installed.
# add <NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/ to your path
arm64_android_hello: hello.c
	aarch64-linux-android29-clang -Wall -O2 -s $< -o $@

arm64_posix_syscall: posix_syscall.c
	aarch64-linux-gnu-gcc -Wall -O2 -s $< -o $@

mips32el_hello: hello.c
	mipsel-linux-gnu-gcc -Wall -O2 -s $< -o $@

mips32el_hello_static: hello.c
	mipsel-linux-gnu-gcc -Wall -O2 -s -static $< -o $@

mips32el_posix_syscall: posix_syscall.c
	mipsel-linux-gnu-gcc -Wall -O2 -s $< -o $@ 

x86_hello: hello.c
	gcc -Wall -O2 -s -m32 $< -o $@

x86_hello_static: hello.c
	gcc -Wall -O2 -s -m32 -static $< -o $@

x86_posix_syscall: posix_syscall.c
	gcc -Wall -O2 -s -m32 $< -o $@

x8664_hello: hello.c
	gcc -Wall -O2 -s $< -o $@

x8664_hello_static: hello.c
	gcc -Wall -O2 -s -static $< -o $@

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.d *.s *.o $(TARGET)
