VERSION=$(shell awk '/define version/ { print $$3 }' kbdconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))

CFLAGS += $(RPM_OPT_FLAGS) -DVERSION=\"$(VERSION)\"

LOADLIBES = -lnewt -lpopt
SUBDIRS = po man

all:	subdirs kbdconfig

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

kbdconfig: kbdconfig.c

install:
	mkdir -p $(INSTROOT)/usr/sbin $(INSTROOT)/usr/man/man8
	install -m 755 -s kbdconfig $(INSTROOT)/usr/sbin/kbdconfig
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE) INSTROOT=$(INSTROOT) install) \
	    || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

clean:
	rm -f kbdconfig
	make -C po clean

archive:
	cvs tag -F $(CVSTAG) .
	@rm -rf /tmp/kbdconfig-$(VERSION) /tmp/kbdconfig
	@cd /tmp; cvs export -r$(CVSTAG) kbdconfig
	@mv /tmp/kbdconfig /tmp/kbdconfig-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/kbdconfig-$(VERSION).tar.gz kbdconfig-$(VERSION)
	@rm -rf /tmp/kbdconfig-$(VERSION)
	@echo "The archive is in kbdconfig-$(VERSION)"
