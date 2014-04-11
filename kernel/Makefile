TOPDIR=.
archtype= x86
MODFLAGS= ARCH=$(archtype) SUBARCH=32
# KERNEL_DIR(the source kernel directory)
KDIR=${KERNEL_DIR}

KDIR_kdb=${KDIR}_kdb
# the kernel module directory
MODULE_DIR=/usr/lib/modules
# Common flags to be passed for driver compilation
EXTRA_CFLAGS += -Winline -Wall 
EXTRA_CFLAGS += -D__KERNEL__ -DKERNEL_V_2632 

default: all

obj-m    := arp_defense.o
arp_defense-objs := hook.o arp_hook.o arp_hash.o arp_nl.o
all: 
	$(MAKE) -C $(KDIR) M=$(PWD) $(MODFLAGS) modules

kdb:
	$(MAKE) -C $(KDIR_kdb) M=$(PWD) $(MODFLAGS) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(MODFLAGS) clean
	rm -rf $(MODULE_DIR)/arp_defense.ko
install: 
	mkdir -p ${MODULE_DIR}
	cd $(TOPDIR); $(CP) -af *.ko $(MODULE_DIR)
