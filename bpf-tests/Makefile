CC=gcc
CFLAGS=-g
#CFLAGS+=-L`realpath /linux/tools/lib/bpf`
#INCLUDES=-I`realpath /linux/tools/lib` -I`realpath /linux/usr/include` -I`realpath /linux/include` -I`realpath /linux/arch/x86/include`
#LDFLAGS=-lbpf
LDFLAGS=-lopcodes

# Enter program link
APP = binary-func-writer

all: $(APP)

$(APP): $(APP).c
	$(CC) $(CFLAGS) $(INCLUDES) $< $(LDFLAGS) -o $@
