VERSION=$(shell awk '/Version:/ { print $$2 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PACKAGE = authconfig
BINARIES = authconfig
DATA=authconfig.glade authconfig-gtk.py
PYTHONMODULES = authconfigmodule.so
PYTHONREV=2.2
PYTHONINC=/usr/include/python$(PYTHONREV)
PYTHONLIB=/usr/lib/python$(PYTHONREV)/site-packages

CFLAGS = -g3 -Wall -fPIC -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
CFLAGS += $(shell pkg-config --cflags glib-2.0 libglade-2.0) -I$(PYTHONINC)
CFLAGS += -DG_DISABLE_DEPRECATED -DGTK_DISABLE_DEPRECATED $(RPM_OPT_FLAGS)
RESOLVLIBS=-lresolv
LIBS = -lnewt -lpopt $(RESOLVLIBS)
GLIBLIBS = $(shell pkg-config --libs glib-2.0)
LIBGLADELIBS = $(shell pkg-config --libs libglade-2.0)
SUBDIRS = po man

DESTDIR=
datadir=/usr/share
mandir=/usr/share/man
sbindir=/usr/sbin
CFLAGS += -DDATADIR=\"$(datadir)\"

all:	subdirs $(BINARIES) $(PYTHONMODULES)

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

authconfig: authconfig.o authinfo.o shvar.o dnsclient.o
	$(CC) -o $@ $^ $(GLIBLIBS) $(LIBS)

authconfigmodule.so: authconfigmodule.o authinfo.o shvar.o dnsclient.o
	$(CC) -o $@ -shared -fPIC $^ $(GLIBLIBS) $(RESOLVLIBS)
	python$(PYTHONREV) -c 'import authconfig'

install:
	mkdir -p $(DESTDIR)$(sbindir)
	mkdir -p $(DESTDIR)$(PYTHONLIB)
	mkdir -p $(DESTDIR)$(datadir)/$(PACKAGE)
	mkdir -p $(DESTDIR)$(datadir)/firstboot/modules

	install -m 755 $(BINARIES) $(DESTDIR)$(sbindir)/
	install -m 755 $(PYTHONMODULES) $(DESTDIR)$(PYTHONLIB)/
	install -m 644 $(DATA) $(DESTDIR)$(datadir)/$(PACKAGE)/
	chmod 755 $(DESTDIR)$(datadir)/$(PACKAGE)/*.py
	python -c "import compileall; compileall.compile_dir(\""$(DESTDIR)$(datadir)/$(PACKAGE)"\", 2, \""$(datadir)/$(PACKAGE)"\", 1)"
	cd  $(DESTDIR)$(datadir)/firstboot/modules ; ln -s -f ../../$(PACKAGE)/*.py* .

	mkdir -p $(DESTDIR)$(mandir)/man8
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE) sbindir=$(sbindir) install) \
	    || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

clean:
	rm -f authconfig authconfig-gtk *.o
	make -C po clean

archive:
	cvs -d `cat CVS/Root` tag -cFR $(CVSTAG) .
	@rm -rf /tmp/$(PACKAGE)-$(VERSION) /tmp/$(PACKAGE)
	@dir=$$PWD; cd /tmp; cvs -d `cat $$dir/CVS/Root` export -r$(CVSTAG) $(PACKAGE)
	@mv /tmp/$(PACKAGE) /tmp/$(PACKAGE)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PACKAGE)-$(VERSION).tar.gz \
		$(PACKAGE)-$(VERSION)
	@rm -rf /tmp/$(PACKAGE)-$(VERSION)
	@echo "The archive is in $(PACKAGE)-$(VERSION).tar.gz"
