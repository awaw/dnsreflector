PROG=dnsreflector
MAN=dnsreflector.1

BINDIR=/usr/local/sbin

CC=gcc
CFLAGS+=-g -Wall -Werror

VERS=1.01
LVERS="$(PROG) $(VERS) (`date +%Y-%b-%d`)"
dist:
	rm -rf /tmp/dnsreflector-$(VERS)/
	mkdir /tmp/dnsreflector-$(VERS)/
	cp -pR * /tmp/dnsreflector-$(VERS)/
	cd /tmp/dnsreflector-$(VERS)/ && make cleandir
	cd /tmp/dnsreflector-$(VERS)/ && rm -rf ./CVS/
	(echo $(LVERS); cat README) >/tmp/dnsreflector-$(VERS)/README
	cd /tmp && tar cf dnsreflector-$(VERS).tar ./dnsreflector-$(VERS)/
	cd /tmp && gzip -f9 dnsreflector-$(VERS).tar
	cd /tmp && rm -rf ./dnsreflector-$(VERS)/

.include <bsd.prog.mk>
