probe-objs := src/main.o src/core.o src/verify.o
test_probe-objs := test/test_main.o lib/core.o

ifeq ($(TARGET),test)
obj-m := test_probe.o
else
obj-m := probe.o
endif

ccflags-y += -Isrc
ccflags-y += -std=gnu11
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes

ifeq ($(KDIR),)
$(error KDIR must be set, e.g. "make KDIR=/path/to/kernel-source")
endif
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
