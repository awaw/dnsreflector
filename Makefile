# $Id: Makefile,v 1.7 2003/05/01 13:12:56 armin Exp $

PROG=dnsreflector
SRCS=dnsreflector.c
MAN=dnsreflector.1

BINDIR=/usr/local/sbin
MANDIR=/usr/local/man/cat

CFLAGS+=-g -Wall -Werror

VERS=1.02
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
