VERSION=$(shell awk '/Version:/ { print $$2 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PROGNAME = authconfig

CFLAGS += -Wall -DVERSION=\"$(VERSION)\" `glib-config --cflags` -ggdb $(RPM_OPT_FLAGS)
LOADLIBES = `glib-config --libs` -lnewt -lpopt
SUBDIRS = po man

all:	subdirs $(PROGNAME)

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

authconfig: $(PROGNAME).o authinfo.o shvar.o

install:
	mkdir -p $(INSTROOT)/usr/sbin $(INSTROOT)/usr/man/man8
	mkdir -p $(INSTROOT)/etc/pam.d
	install -m 755 $(PROGNAME) $(INSTROOT)/usr/sbin/$(PROGNAME)
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
