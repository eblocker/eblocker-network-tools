TARGET_ARCH :=$(shell uname -m)

all: arp_read arp_write dhcp_discover script_wrapper

arp_read: arp_read.c
	gcc -std=gnu11 -o arp_read arp_read.c -lpcap -lhiredis

arp_write: arp_write.c
	gcc -std=gnu11 -o arp_write arp_write.c -lnet -lhiredis

dhcp_discover: dhcp_discover.c
	gcc -o dhcp_discover dhcp_discover.c -lnet -lpcap

script_wrapper: script_wrapper.c
	gcc -o script_wrapper script_wrapper.c

# Where to put executable commands on 'make install'?
BIN = $(DESTDIR)/opt/eblocker-network/bin
SYSTEMD = $(DESTDIR)/lib/systemd/system

install: all
	install -d $(BIN)
	install ./arp_read $(BIN)
	install ./arp_write $(BIN)
	install ./dhcp_discover $(BIN)
	install ./script_wrapper $(BIN)
	install -d $(SYSTEMD)
	install ./etc/arpwrite.service $(SYSTEMD)
	install ./etc/arpread.service $(SYSTEMD)

clean:
	rm -f arp_read arp_write dhcp_discover script_wrapper

package:
	dpkg-buildpackage -us -uc

