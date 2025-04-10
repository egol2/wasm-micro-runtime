CC=gcc
# CFLAGS=-g -O0
CFLAGS=-O3
#CFLAGS+=-L`realpath /linux/tools/lib/bpf`
#INCLUDES=-I`realpath /linux/tools/lib` -I`realpath /linux/usr/include` -I`realpath /linux/include` -I`realpath /linux/arch/x86/include`
#LDFLAGS=-lbpf
LDFLAGS=-lopcodes

# Enter program link
APP = binary-func-writer
APP2 = execution-tester

all: $(APP) $(APP2)

$(APP): $(APP).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o

$(APP2): $(APP2).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o
