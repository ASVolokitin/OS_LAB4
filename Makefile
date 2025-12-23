obj-m += vtfs.o

vtfs-objs := source/vtfs.o source/vtfs_backend_ram.o

PWD := $(CURDIR) 
KDIR = /lib/modules/`uname -r`/build
EXTRA_CFLAGS = -Wall -g

CC = gcc
CFLAGS = -O2 -Wall
LDLIBS = -luring

all:
	make -C $(KDIR) M=$(PWD) modules 

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -rf .cache

async_uring: async_uring.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)