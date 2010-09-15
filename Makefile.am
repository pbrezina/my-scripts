SUBDIRS = po man icons

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
pkgdata_DATA = authconfig.glade authinfo.py shvfile.py dnsclient.py msgarea.py
pythonsite_LTLIBRARIES = acutilmodule.la
backupdir = $(localstatedir)/lib/authconfig
backup_DATA =

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
	touch $(DESTDIR)/$(pamdir)/password-auth-ac
	touch $(DESTDIR)/$(pamdir)/fingerprint-auth-ac
	touch $(DESTDIR)/$(pamdir)/smartcard-auth-ac
	mkdir -p $(DESTDIR)/$(datadir)/applications
	desktop-file-install \
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
	authconfig.desktop.in $(pkgdata_SCRIPTS) $(pkgdata_DATA) \
	NOTES utf8ify-mo \
	intltool-extract.in intltool-merge.in intltool-update.in \
	$(pixmap_DATA) README.samba3 mkinstalldirs authconfig.glade.h \
	$(sbin_SCRIPTS)
DISTCLEANFILES = intltool-extract intltool-merge intltool-update authconfig.desktop

VERSION=@PACKAGE_VERSION@
TAG=$(shell echo r-$(VERSION) | sed 's,\.,-,g')
distdir=$(PACKAGE)-$(VERSION)

authconfig.glade.h: authconfig.glade
	$(INTLTOOL_EXTRACT) --type=gettext/glade $<

update-po: authconfig.glade.h
	$(MAKE) -C po update-po

tag:
	hg tag $(TAG)

force-tag forcetag:
	hg tag --force $(TAG)

archive:
	rm -fr /tmp/$(PACKAGE) $(PACKAGE)-$(VERSION).tar.bz2
	mkdir /tmp/$(PACKAGE) && \
	hg archive -r $(TAG) /tmp/$(PACKAGE)/$(distdir) && \
	(cd /tmp/$(PACKAGE)/$(distdir) && \
	./autogen.sh && \
	./configure && \
	make dist) && \
	mv /tmp/$(PACKAGE)/$(distdir)/$(distdir).tar.bz2 .
