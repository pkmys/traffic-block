TARGET:= traffic_filter
PWD:= $(shell pwd)
KERNDIR:= "/lib/modules/$(shell uname -r)/build/"
DNS:= dns
UTIL:= util

ccflags-y:= -Werror
ifeq (${DEBUG},1)
ccflags-y+= -DTF_DEBUG_SKB -DDEBUG_DEBUG
endif
obj-m:= ${TARGET}.o
${TARGET}-objs:= ${TARGET}_mod.o ${DNS}.o ${UTIL}.o

all:
	make -C ${KERNDIR} M=${PWD}  modules
	gcc traffic_filter.c -o tb
# generate public private pair key 
	openssl req -x509 -new -nodes -utf8 -sha256 -days 36500 \
	-batch -config openssl_x509.config -outform DER \
	-out public_key.der -keyout private_key.priv
# sign kernel module
	/usr/src/linux-headers-$(shell uname -r)/scripts/sign-file \
	sha256 private_key.priv public_key.der 	${TARGET}.ko

clean:
	make -C ${KERNDIR} M=${PWD}  clean
	rm -f *.priv *.der
	rm -f tb

rebuild: clean all