SUBDIRS = po man

@INTLTOOL_DESKTOP_RULE@

PYTHONREV=@PYTHONREV@
pythonincdir = $(includedir)/python@PYTHONREV@
pythonsitedir = $(libdir)/python@PYTHONREV@/site-packages
pamdir = $(sysconfdir)/pam.d
consoledir = $(sysconfdir)/security/console.apps
sysconfigdir = $(sysconfdir)/sysconfig
applnkdir = $(sysconfdir)/X11/applnk/System
startheredir = $(sysconfdir)/X11/sysconfig

sbin_SCRIPTS = cacertdir_rehash
pkgdata_SCRIPTS = authconfig-gtk.py authconfig.py
pkgdata_DATA = authconfig.glade authinfo.py shvfile.py dnsclient.py
pythonsite_LTLIBRARIES = acutilmodule.la
pixmapdir = $(datadir)/pixmaps
pixmap_DATA = user_auth.png

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(sbindir)
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig-tui
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig-gtk
	ln -sf consolehelper $(DESTDIR)/$(bindir)/system-config-authentication
	ln -sf $(pkgdatadir)/authconfig.py $(DESTDIR)/$(sbindir)/authconfig
	ln -sf $(pkgdatadir)/authconfig-tui.py $(DESTDIR)/$(sbindir)/authconfig-tui
	ln -sf $(pkgdatadir)/authconfig-gtk.py $(DESTDIR)/$(sbindir)/authconfig-gtk
	ln -sf $(pkgdatadir)/authconfig-gtk.py $(DESTDIR)/$(sbindir)/system-config-authentication

install-data-local: authconfig.desktop
	mkdir -p $(DESTDIR)/$(pamdir)
	mkdir -p $(DESTDIR)/$(consoledir)
	mkdir -p $(DESTDIR)/$(sysconfigdir)
	mkdir -p $(DESTDIR)/$(applnkdir)
	mkdir -p $(DESTDIR)/$(startheredir)
	mkdir -p $(DESTDIR)/$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig-tui
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/system-config-authentication
	$(INSTALL_DATA) $(srcdir)/authconfig.console $(DESTDIR)/$(consoledir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig-tui.console $(DESTDIR)/$(consoledir)/authconfig-tui
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/system-config-authentication
	ln -sf authconfig.py $(DESTDIR)/$(pkgdatadir)/authconfig-tui.py
	touch $(DESTDIR)/$(sysconfigdir)/authconfig
	touch $(DESTDIR)/$(pamdir)/system-auth-ac
	mkdir -p $(DESTDIR)/$(datadir)/applications
	desktop-file-install --vendor redhat \
		--add-category=X-Red-Hat-Base \
		--add-category=Application \
		--add-category=System \
		--dir=$(DESTDIR)/$(datadir)/applications \
		authconfig.desktop

uninstall-local:
	$(RM) $(DESTDIR)/$(bindir)/authconfig
	$(RM) $(DESTDIR)/$(bindir)/authconfig-tui
	$(RM) $(DESTDIR)/$(bindir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(bindir)/system-config-authentication
	$(RM) $(DESTDIR)/$(pamdir)/authconfig
	$(RM) $(DESTDIR)/$(pamdir)/authconfig-tui
	$(RM) $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(pamdir)/system-config-authentication
	$(RM) $(DESTDIR)/$(consoledir)/authconfig
	$(RM) $(DESTDIR)/$(consoledir)/authconfig-tui
	$(RM) $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(consoledir)/system-config-authentication
	$(RM) $(DESTDIR)/$(sysconfigdir)/authconfig
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	$(RM) $(DESTDIR)$(pkgdatadir)/authconfig-tui.py
	rmdir $(DESTDIR)/$(applnkdir)
	rmdir $(DESTDIR)/$(startheredir)
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(consoledir)
	rmdir $(DESTDIR)/$(sysconfigdir)

AM_CFLAGS = @CFLAGS@ @PYTHON_CFLAGS@ -Wall

acutilmodule_la_SOURCES = acutilmodule.c
acutilmodule_la_LDFLAGS = -module -avoid-version -export-dynamic @LDFLAGS@

EXTRA_DIST = authconfig.spec.in authconfig.spec authconfig.pamd \
	authconfig.console authconfig-tui.console authconfig-gtk.console \
	authconfig.desktop.in authconfig.py authinfo.py \
	shvfile.py dnsclient.py authconfig-gtk.py authconfig.glade \
	man/en/authconfig.8 man/en/authconfig-tui.8 man/en/system-auth-ac.5 \
	NOTES utf8ify-mo \
	intltool-extract.in intltool-merge.in intltool-update.in \
	user_auth.png README.samba3 mkinstalldirs authconfig.glade.h \
	cacertdir_rehash
DISTCLEANFILES = intltool-extract intltool-merge intltool-update authconfig.desktop

VERSION=@PACKAGE_VERSION@
TAG=$(shell echo r-$(VERSION) | sed 's,\.,-,g')
distdir=$(PACKAGE)-$(VERSION)

authconfig.glade.h: authconfig.glade
	$(INTLTOOL_EXTRACT) --type=gettext/glade $<

update-po: authconfig.glade.h
	$(MAKE) -C po update-po
	cp po/sr@latin.po po/sr.latin.po

tag:
	cvs tag -cR $(TAG)

force-tag forcetag:
	cvs tag -cFR $(TAG)

authconfig.spec: authconfig.spec.in configure.in
	./autogen.sh

archive:
	rm -fr /tmp/$(PACKAGE) $(PACKAGE)-$(VERSION).tar.bz2
	dir=`pwd` ; \
	root=`cat CVS/Root` ; \
	cd /tmp ; \
	cvs -d "$$root" export -r $(TAG) -d $(PACKAGE) $(PACKAGE) ; \
	cd $(PACKAGE) ; \
	mv po/sr.latin.po po/sr@latin.po ; \
	./autogen.sh ; \
	./configure ; \
	aclocal ; \
	make dist ; \
	mv $(distdir).tar.bz2 $$dir
