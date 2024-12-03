CC=gcc
CFLAGS_hook.o := -DDEBUG
KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
obj-m += hook.o

hook: hook.c
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
