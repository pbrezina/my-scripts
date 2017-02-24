SUBDIRS = po man

@INTLTOOL_DESKTOP_RULE@

PYTHONREV=@PYTHONREV@
pythonsitedir = $(libdir)/python@PYTHONREV@/site-packages
pamdir = $(sysconfdir)/pam.d
consoledir = $(sysconfdir)/security/console.apps
sysconfigdir = $(sysconfdir)/sysconfig

sbin_SCRIPTS = cacertdir_rehash
pkgdata_SCRIPTS = authconfig.py
pkgdata_DATA = authinfo.py shvfile.py dnsclient.py
pythonsite_LTLIBRARIES = acutil.la
backupdir = $(localstatedir)/lib/authconfig

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(sbindir)
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig
	ln -sf $(pkgdatadir)/authconfig.py $(DESTDIR)/$(sbindir)/authconfig

install-data-local: authconfig.desktop
	mkdir -p $(DESTDIR)/$(pamdir)
	mkdir -p $(DESTDIR)/$(consoledir)
	mkdir -p $(DESTDIR)/$(sysconfigdir)
	mkdir -p $(DESTDIR)/$(pkgdatadir)
	mkdir -p $(DESTDIR)/$(backupdir)
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig.console $(DESTDIR)/$(consoledir)/authconfig
	touch $(DESTDIR)/$(sysconfigdir)/authconfig
	touch $(DESTDIR)/$(pamdir)/system-auth-ac
	touch $(DESTDIR)/$(pamdir)/password-auth-ac
	touch $(DESTDIR)/$(pamdir)/fingerprint-auth-ac
	touch $(DESTDIR)/$(pamdir)/smartcard-auth-ac
	touch $(DESTDIR)/$(pamdir)/postlogin-ac
	mkdir -p $(DESTDIR)/$(datadir)/applications
	desktop-file-install \
		--dir=$(DESTDIR)/$(datadir)/applications \
		authconfig.desktop

uninstall-local:
	$(RM) $(DESTDIR)/$(bindir)/authconfig
	$(RM) $(DESTDIR)/$(pamdir)/authconfig
	$(RM) $(DESTDIR)/$(consoledir)/authconfig
	$(RM) $(DESTDIR)/$(sysconfigdir)/authconfig
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	rmdir $(DESTDIR)/$(applnkdir)
	rmdir $(DESTDIR)/$(startheredir)
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(consoledir)
	rmdir $(DESTDIR)/$(sysconfigdir)

AM_CFLAGS = @CFLAGS@ @PYTHON_CFLAGS@ -Wall

acutil_la_SOURCES = acutilmodule.c
acutil_la_LDFLAGS = -module -avoid-version -export-dynamic @LDFLAGS@

EXTRA_DIST = authconfig.spec.in authconfig.spec authconfig.pamd \
	authconfig.console \
	$(pkgdata_SCRIPTS) $(pkgdata_DATA) \
	NOTES utf8ify-mo \
	intltool-extract.in intltool-merge.in intltool-update.in \
	$(pixmap_DATA) HOWTO.AD-client \
	$(sbin_SCRIPTS)
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

VERSION=@PACKAGE_VERSION@
TAG=$(shell echo r-$(VERSION) | sed 's,\.,-,g')
distdir=$(PACKAGE)-$(VERSION)

update-po:
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
