#
# Author: (C) 2016 Michail Flouris <michail.flouris@onapp.com>

# NOTE: starting from recent kernels (after 3.10) xen blkback supports
# persistent grants and a bit later "multi hardware-queues/rings".

# So in these recent kernels, there is no need for our blkback_mq implementation.

.PHONY: all install clean

all:
	@echo 'Please use the mainline kernel driver after kernel 3.22'
	@exit 0

install:
	@echo 'Please install the mainline kernel driver after kernel 3.22'
	@exit 0

clean:
	\rm -rf *.o .*.o.d .depend *.ko .*.cmd *.mod.c .tmp* Module.*ers modules.order

