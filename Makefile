PWD	:= $(shell pwd)
KDIR	:= /lib/modules/$(shell uname -r)/build

obj-m += k2.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
