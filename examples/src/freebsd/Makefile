CC = gcc

CFLAGS = -Wall -O2 -s

#CFLAGS += -DDEBUG

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

DEPS = $(patsubst %.o,%.d,$(OBJS))
CFLAGS += -MD
MISSING_DEPS = $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES = $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

LIBS=

TARGET = x8664_hello x8664_hello_static

all : $(TARGET)

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

x8664_hello: hello.c
	gcc -Wall -O2 -s $< -o $@

x8664_hello_static: hello.c
	gcc -Wall -O2 -s -static $< -o $@

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.d *.s *.o $(TARGET)
