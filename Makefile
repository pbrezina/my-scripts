VERSION=$(shell awk '/define version/ { print $$3 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PROGNAME = authconfig

CFLAGS += -Wall -DVERSION=\"$(VERSION)\" -g

LOADLIBES = -lnewt -lpopt
SUBDIRS = po man

all:	subdirs $(PROGNAME)

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

authconfig: $(PROGNAME).c

install:
	mkdir -p $(INSTROOT)/usr/sbin $(INSTROOT)/usr/man/man8
	install -m 755 -s $(PROGNAME) $(INSTROOT)/usr/sbin/$(PROGNAME)
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE) INSTROOT=$(INSTROOT) install) \
	    || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

clean:
	rm -f $(PROGNAME)
	make -C po clean

archive:
	cvs tag -F $(CVSTAG) .
	@rm -rf /tmp/$(PROGNAME)-$(VERSION) /tmp/$(PROGNAME)
	@cd /tmp; cvs export -r$(CVSTAG) $(PROGNAME)
	@mv /tmp/$(PROGNAME) /tmp/$(PROGNAME)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROGNAME)-$(VERSION).tar.gz \
		$(PROGNAME)-$(VERSION)
	@rm -rf /tmp/$(PROGNAME)-$(VERSION)
	@echo "The archive is in $(PROGNAME)-$(VERSION).tar.gz"
