SUBDIRS = po man

@INTLTOOL_DESKTOP_RULE@

PYTHONREV=@PYTHONREV@
pythonsitedir = $(libdir)/python@PYTHONREV@/site-packages
pamdir = $(sysconfdir)/pam.d
sysconfigdir = $(sysconfdir)/sysconfig

sbin_SCRIPTS = cacertdir_rehash
pkgdata_SCRIPTS = authconfig.py
pkgdata_DATA = authinfo.py shvfile.py dnsclient.py
pythonsite_LTLIBRARIES = acutil.la
backupdir = $(localstatedir)/lib/authconfig

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(sbindir)
	ln -sf $(pkgdatadir)/authconfig.py $(DESTDIR)/$(sbindir)/authconfig

install-data-local:
	mkdir -p $(DESTDIR)/$(pamdir)
	mkdir -p $(DESTDIR)/$(sysconfigdir)
	mkdir -p $(DESTDIR)/$(pkgdatadir)
	mkdir -p $(DESTDIR)/$(backupdir)
	touch $(DESTDIR)/$(sysconfigdir)/authconfig
	touch $(DESTDIR)/$(pamdir)/system-auth-ac
	touch $(DESTDIR)/$(pamdir)/password-auth-ac
	touch $(DESTDIR)/$(pamdir)/fingerprint-auth-ac
	touch $(DESTDIR)/$(pamdir)/smartcard-auth-ac
	touch $(DESTDIR)/$(pamdir)/postlogin-ac

uninstall-local:
	$(RM) $(DESTDIR)/$(bindir)/authconfig
	$(RM) $(DESTDIR)/$(pamdir)/authconfig
	$(RM) $(DESTDIR)/$(sysconfigdir)/authconfig
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(sysconfigdir)

AM_CFLAGS = @CFLAGS@ @PYTHON_CFLAGS@ -Wall

acutil_la_SOURCES = acutilmodule.c
acutil_la_LDFLAGS = -module -avoid-version -export-dynamic @LDFLAGS@

EXTRA_DIST = authconfig.spec.in authconfig.spec \
	$(pkgdata_SCRIPTS) $(pkgdata_DATA) \
	NOTES utf8ify-mo \
	intltool-extract.in intltool-merge.in intltool-update.in \
	$(pixmap_DATA) HOWTO.AD-client \
	$(sbin_SCRIPTS)
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

VERSION=@PACKAGE_VERSION@
TAG=authconfig-$(VERSION)
distdir=$(PACKAGE)-$(VERSION)

update-po:
	$(MAKE) -C po update-po

tag:
	git tag $(TAG)
