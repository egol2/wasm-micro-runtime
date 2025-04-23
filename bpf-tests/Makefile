CC=gcc
# CFLAGS=-g -O0
CFLAGS=-O3
#CFLAGS+=-L`realpath /linux/tools/lib/bpf`
#INCLUDES=-I`realpath /linux/tools/lib` -I`realpath /linux/usr/include` -I`realpath /linux/include` -I`realpath /linux/arch/x86/include`
#LDFLAGS=-lbpf
LDFLAGS=-lopcodes -lbfd

# Enter program link
APP = binary-func-writer
APP2 = execution-tester
APP3 = binary-funct-writer-wasm
APP4 = c-binary-rewriter

all: $(APP) $(APP2) $(APP3) $(APP4)

$(APP): $(APP).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o

$(APP2): $(APP2).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o

$(APP3): $(APP3).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o

$(APP4): $(APP4).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@.o