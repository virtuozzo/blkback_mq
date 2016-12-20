#
# Author: (C) 2012 Michail Flouris <michail.flouris@onapp.com>

# try to detect the Linux distro type
ifneq ($(wildcard /etc/redhat-release),) 
    LINUX_TYPE := Redhat
    CENTOS_VERSION := $(shell cat /etc/redhat-release | grep 'CentOS' | cut -c 16 )
ifeq ($(CENTOS_VERSION),)
	BUILDDIR := $(error CentOS not found! Current makefile support only CentOS. Aborting!)
endif
else 
    LINUX_TYPE := Non_Redhat
endif

# Directory for Module installation
KERNEL_VERSION ?= $(shell uname -r)
BASEKERNDIR := 
MODDIR := /lib/modules/$(KERNEL_VERSION)/kernel/drivers/net/xen-netback/

BKOBJS = netback.o xenbus.o interface.o
KMODNAME = xen-netback

obj-m += $(KMODNAME).o
$(KMODNAME)-objs += $(BKOBJS)

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
#
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
ifeq ($(KERNELRELEASE),)
	#KERNELDIR ?= $(BASEKERNDIR)/lib/modules/$(shell uname -r)/build
	KERNELDIR ?= $(BASEKERNDIR)/lib/modules/$(KERNEL_VERSION)/build
	#PWD := $(shell pwd)
	#SUBDIRS=$(PWD)/kern_code
endif

#EXTRA_CFLAGS += -include include/linux/autoconf.h

#EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=$(CONFIG_XEN_INTERFACE_VERSION)
EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=0x00030203

#EXTRA_CFLAGS += -DCONFIG_XEN_COMPAT=0xffffff -DHAVE_XEN_PLATFORM_COMPAT_H

# unfortunately += does not work as it should...
export EXTRA_CFLAGS := -I$(KERNELDIR)/include/asm/mach-xen -I$(KERNELDIR)/include/xen $(EXTRA_CFLAGS) 

.PHONY: all ins lsm rmm install clean wc

all:
ifneq ($(LINUX_TYPE),Redhat)
	@echo 'Will not build on non-redhat distro'
	@exit 0
else
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

ins:
	/sbin/insmod $(KMODNAME).ko
	@/sbin/lsmod | grep $(KMODNAME)

lsm:
	@/sbin/lsmod | grep $(KMODNAME)

rmm:
	/sbin/rmmod $(KMODNAME).ko

install:
ifneq ($(LINUX_TYPE),Redhat)
	@echo 'Will not build on non-redhat distro'
	@exit 0
else
	mkdir -p $(MODDIR)
	cp $(KMODNAME).ko $(MODDIR)
	/sbin/depmod -a $(KERNEL_VERSION)
endif

clean:
	\rm -rf *.o .*.o.d .depend *.ko .*.cmd *.mod.c .tmp* Module.*ers modules.order
	\rm -f types.vim tags $(TESTS)

wc:
	@echo -n "Code lines (excl. blank lines): "
	@cat *.[ch] | grep -v "^$$" | grep -v "^[ 	]*$$" | wc -l

netbak.o: netback.c common.h
xenbus.o: xenbus.c common.h 
interface.o: interface.c common.h 

tags:: *.[ch]
	@\rm -f tags
	@ctags -R --languages=c

types.vim: *.[ch]
	@echo "==> Updating tags !"
	@\rm -f $@
	@ctags -R --c-types=+gstu -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myTypes\t")} {printf("%s ", $$1)} END{print ""}' > $@
	@ctags -R --c-types=+cd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myDefines\t")} {printf("%s ", $$1)} END{print ""}' >> $@
	@ctags -R --c-types=+v-gstucd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myVariables\t")} {printf("%s ", $$1)} END{print ""}' >> $@

