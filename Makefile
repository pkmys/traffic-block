TARGET:= traffic_filter_mod
PWD:= $(shell pwd)
KERNDIR:= "/lib/modules/$(shell uname -r)/build/"

obj-m:= ${TARGET}.o

all:
	make -C ${KERNDIR} M=${PWD}  modules
	gcc traffic_filter.c -o traffic_filter

clean:
	make -C ${KERNDIR} M=${PWD}  clean
	rm -f traffic_filter