Summary: Text-mode tool for setting up NIS and shadow passwords.
Name: authconfig
Version: 4.3.6
Release: 1
License: GPL
ExclusiveOS: Linux
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-root
Source: %{name}-%{version}.tar.gz
Requires: glibc >= 2.1, pam >= 0.73, glib2, pam >= 0.75-43
Conflicts: pam_krb5 < 1.49
BuildPrereq: pam-devel >= 0.73, newt-devel, glib2-devel, python, python-devel
BuildPrereq: desktop-file-utils

%description 
Authconfig is a terminal mode program which can configure a workstation
to use shadow (more secure) passwords.  Authconfig can also configure a
system to be a client for certain networked user information and
authentication schemes.

%package gtk
Summary: Graphical tool for setting up NIS and shadow passwords.
Group: System Environment/Base
Requires: %{name} = %{version}-%{release}, pygtk2-libglade, pam >= 0.75-37

%description gtk
Authconfig-gtk is a GUI program which can configure a workstation
to use shadow (more secure) passwords.  Authconfig-gtk can also configure
a system to be a client for certain networked user information and
authentication schemes.

%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS -fPIC"; export CFLAGS
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%find_lang %{name}
find $RPM_BUILD_ROOT%{_datadir} -name "*.mo" | xargs ./utf8ify-mo

%clean
rm -rf $RPM_BUILD_ROOT

%files -f %{name}.lang
%defattr(-,root,root)
%doc NOTES TODO
%ghost %config(noreplace) %{_sysconfdir}/sysconfig/authconfig
%{_bindir}/authconfig
%{_sbindir}/authconfig
%{_mandir}/man8/*
%{_libdir}/python*/site-packages/authconfigmodule.so
%config(noreplace) %{_sysconfdir}/pam.d/authconfig
%config(noreplace) %{_sysconfdir}/security/console.apps/authconfig

%files gtk
%defattr(-,root,root)
%{_bindir}/authconfig-gtk
%{_bindir}/redhat-config-authentication
%{_datadir}/%{name}
%config(noreplace) %{_sysconfdir}/pam.d/authconfig-gtk
%config(noreplace) %{_sysconfdir}/pam.d/redhat-config-authentication
%config(noreplace) %{_sysconfdir}/security/console.apps/authconfig-gtk
%config(noreplace) %{_sysconfdir}/security/console.apps/redhat-config-authentication
%{_datadir}/applications/*
%{_datadir}/pixmaps/*

%changelog
* Mon Jul  7 2003 Nalin Dahyabhai <nalin@redhat.com> 4.3.6-1
- translation updates

* Mon Jun 30 2003 Nalin Dahyabhai <nalin@redhat.com>
- add 'redhat-config-authentication' as an alias for authconfig-gtk
- make authconfig-gtk exec authconfig if gui startup fails and it looks like
  we're connected to a tty

* Thu Jun 05 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon May  5 2003 Nalin Dahyabhai <nalin@redhat.com> 4.3.5-1
- translation updates
- close unusable file descriptors if locking fails

* Tue Feb 18 2003 Nalin Dahyabhai <nalin@redhat.com> 4.3.4-1
- learn how to toggle defaults/crypt_style in /etc/libuser.conf (#79337)

* Fri Feb  7 2003 Nalin Dahyabhai <nalin@redhat.com> 4.3.3-1
- look in /lib64 for modules for nsswitch and PAM by default on
  x86_64, ppc64, and s390x (#83049)

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt
 
* Mon Nov  4 2002 Nalin Dahyabhai <nalin@redhat.com> 4.3.2-1
- update translations
- update copyright strings (only took 10 months!)

* Wed Oct 23 2002 Nalin Dahyabhai <nalin@redhat.com> 4.3.1-1
- require a version of PAM (0.75-43) which supports $ISA
- use $ISA in our own PAM config files

* Tue Oct 22 2002 Nalin Dahyabhai <nalin@redhat.com>
- add $ISA to the name of the directory in which we expect PAMs to be stored

* Fri Sep 20 2002 Nalin Dahyabhai <nalin@redhat.com> 4.3-1
- build with -fPIC, necessary on some arches

* Tue Sep  3 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.11-3
- update translations

* Thu Aug 29 2002 Trond Eivind Glomsrød <teg@redhat.com> 4.2.12-2
- Update translations

* Fri Aug 23 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.11-1
- modify spacing and layout in authconfig-gtk

* Thu Aug 15 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.10-4
- translation updates
- rebuild to pick up dependency changes

* Mon Jul 29 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.10-3
- include the userhelper configuration file
- require sufficiently-new pam package in the gui subpackage

* Fri Jul 26 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.10-2
- actually include the icon in the package
- translation updates

* Tue Jul 23 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.10-1
- use desktop-file-install (#69376)
- include an icon for the menu item (#68577)

* Wed Jul 17 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.9-2
- own the pkgdatadir
- pull in translation updates

* Mon Jun  3 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.9-1
- add --enable-experimental to enable some of that experimental code
- add --enable-local to enable local policies
- update translations

* Thu May 30 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-7
- use the current revision of python by default
- get the intltool/gettext situation sorted out

* Thu May 23 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Fri May  3 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-5
- remove bogus buildrequires left over from when authconfig-gtk was C code
- buildrequires python-devel in addition to python (to build the python module,
  but we still need python to byte-compile the python script)

* Thu Apr 18 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-4
- add missing translations back in
- convert .mo files at install-time

* Mon Apr 15 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-3
- refresh translations

* Wed Apr 10 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-2
- actually add the .desktop files

* Tue Apr  9 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.8-1
- refresh translations
- destroy the python object correctly

* Tue Mar 26 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.7-2
- add the .desktop file

* Mon Mar 25 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.7-1
- rework the auth stack logic to require all applicable auth modules

* Fri Mar  1 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.6-1
- allow pam_krb5afs to be used for account management, too

* Mon Feb 25 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.5-3
- refresh translations

* Fri Feb 22 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.5-2
- refresh translations

* Tue Feb 12 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.5-1
- actually free authInfo structures when asked to
- use pam_krb5's account management facilities
- conflict with versions of pam_krb5 which don't offer account management

* Mon Feb  4 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.4-1
- add python bindings for the back-end
- redo the gui so that it exercises the python bindings
- take a shot at getting authconfig to work in a firstboot container

* Thu Jan 31 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.3-4
- rebuild again

* Wed Jan 30 2002 Tim Powers <timp@redhat.com> 4.2.3-3
- rebuilt against new glib

* Wed Jan 23 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.3-2
- rebuild in new environment

* Thu Jan 10 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.3-1
- add some more experimental options
- clean up the glade files a bit
- don't destroy a garbage pointer on main cancel, destroy the main dialog

* Thu Jan  3 2002 Nalin Dahyabhai <nalin@redhat.com> 4.2.2-2
- bump release and rebuild

* Thu Dec 20 2001 Nalin Dahyabhai <nalin@redhat.com> 4.2.2-1
- make setting of experimental options only possible through
  /etc/sysconfig/authconfig, to keep accidents from happening
- add some more support for experimental stuff

* Tue Dec 11 2001 Nalin Dahyabhai <nalin@redhat.com> 4.2.1-1
- fix setting of LDAP TLS option in authconfig-gtk
- change Apply to Ok, Close to Cancel, because that's how they work

* Tue Dec 11 2001 Nalin Dahyabhai <nalin@redhat.com> 4.2-2
- add the glade XML file to the -gtk subpackage (fix from katzj)

* Mon Dec 10 2001 Nalin Dahyabhai <nalin@redhat.com> 4.2-1
- port to glib2
- move post code to the back-end
- add a libglade GUI in a -gtk subpackage
- set up to use userhelper

* Tue Nov 27 2001 Nalin Dahyabhai <nalin@redhat.com>
- remove pam_winbind from the list of session modules, because it doesn't
  provide a session-management interface

* Mon Sep 24 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.20-1
- make pam_localuser sufficient after pam_unix in account management, to allow
  local users in even if network connections to the LDAP directory are down (the
  network users should fail when pam_ldap returns a system error)

* Thu Sep  6 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.19-1
- translation refresh

* Tue Aug 28 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix assertion error hitting glib (#51798)
- allow multiple ldap servers to be specified (#49864)

* Fri Aug 24 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.18-1
- pam_ldap shouldn't be a mandatory module (#52531)
- refresh translations

* Thu Aug 23 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.17-1
- make pam_ldap required for account management when ldapauth is enabled
  (this requires pam_ldap 114 or later, but simplifies things)
- more translation updates

* Wed Aug 22 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.16-1
- warn about nscd the same way we do about nss_ldap and pam_krb5
- reorder some internal code so that it's easier to maintain
- change help string about the --probe option to make it clearer that using
  it doesn't actually set any options
- update translations from CVS

* Tue Aug 21 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.15-1
- set "pam_password md5" instead of "pam_password crypt" in ldap.conf if MD5
  is enabled

* Mon Aug 20 2001 Nalin Dahyabhai <nalin@redhat.com> 4.1.14-1
- right justify labels, and remove padding

* Fri Aug 17 2001 Nalin Dahyabhai <nalin@redhat.com>
- update translations from CVS, fixing #51873

* Thu Aug 16 2001 Nalin Dahyabhai <nalin@redhat.com>
- set "pam_password crypt" in ldap.conf if not previously set
- update translations

* Mon Aug  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't mess with krb4 config files if we have no realm
- update translations

* Mon Jul 30 2001 Nalin Dahyabhai <nalin@redhat.com>
- use USESHADOW, USENIS, USEHESIOD, and USESMBAUTH variables to
  /etc/sysconfig/authconfig
- update translations

* Mon Jul  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- add "type=" to the list of arguments set up for pam_cracklib
- also modify /etc/krb.conf when configuring Kerberos (for compatibility)
- add --enablecache and --disablecache, which duplicates some of ntsysv's
  functionality, but it belongs here, too
- bravely try to carry on if bad options are passed in during kickstart

* Mon Jun 25 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix man page reference to file (/etc/sysconfig/authconfig, not auth) (#43344)
- own /etc/sysconfig/authconfig (#43344)
- fix spelling errors in Japanese message files (#15984)

* Tue Jun 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- rename --{enable,disable}smb to --{enable,disable}smbauth

* Thu May 31 2001 Nalin Dahyabhai <nalin@redhat.com>
- add --probe option to guess at LDAP and Kerberos configuration using DNS
- add preliminary support for SMB authentication

* Wed Feb 14 2001 Preston Brown <pbrown@redhat.com>
- final translation update.
- langify

* Mon Feb 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- errors connecting to LDAP also trigger service_err returns, so ignore on
  those as well

* Fri Feb  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- handle the case where the user doesn't specify a Kerberos realm, but
  enables it anyway
- update translations

* Wed Feb  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- remove pam_access from the default configuration -- swat, pop, imap, etc.
  don't define a tty and pam_access bails if one isn't set

* Tue Feb  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- ignore on errors connecting to LDAP servers when doing LDAP account mgmt
  (probably less secure, but it allows root to log in when a wrong server
  name has been specified or the server is down)

* Mon Feb  5 2001 Nalin Dahyabhai <nalin@redhat.com>
- make account management in system-auth be an AND operation, but ignore
  user_unknown status for pam_ldap account management so that local root
  can log in (#26029)
- add pam_access and pam_env (#16170) to default configuration

* Tue Jan 24 2001 Preston Brown <pbrown@redhat.com>
- final translation update before Beta

* Tue Jan 24 2001 Nalin Dahyabhai <nalin@redhat.com>
- update translations
- make the entry fields on the second screen just a *little* bit smaller

* Fri Jan 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- really fix #23016 this time
- add buildprereqs on pam-devel, newt-devel, and glib-devel

* Wed Jan 10 2001 Nalin Dahyabhai <nalin@redhat.com>
- match nss_ldap change of flag definitions for "ssl" flag ("on"=>"start_tls")
- change the "nothing-enabled" default so that we don't mistakenly think that
  NIS is enabled later on when it isn't supposed to be (#23327)
- only enable LDAP-related entry stuff on the appropriate screens (#23328)

* Sat Dec 30 2000 Nalin Dahyabhai <nalin@redhat.com>
- make the copyright message translateable (#23016)

* Fri Dec 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- split the one big help message into multiple help messages (#23017)

* Wed Dec 12 2000 Nalin Dahyabhai <nalin@redhat.com>
- don't write out configuration files for NIS, LDAP, Kerberos, Hesiod unless
  they're enabled when the user quits (we always write NSS, PAM, network)

* Fri Dec  8 2000 Nalin Dahyabhai <nalin@redhat.com>
- make the internal code reflect the external use of "tls" instead of "ssl"

* Thu Dec  7 2000 Nalin Dahyabhai <nalin@redhat.com>
- add support for toggling TLS on and off in /etc/ldap.conf

* Wed Nov 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- don't bother with USESHADOW; testing for /etc/shadow is sufficient
- use newtGrids to make NLS text fit (mostly)
- also edit "hosts:" to make sure it's there if nsswitch.conf is gone or broken
- preserve use of "db" and "nisplus" sources, even though we don't set them up

* Mon Nov 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- add the "nis" flag to pam_unix when NIS is enabled

* Wed Oct  4 2000 Nalin Dahyabhai <nalin@redhat.com>
- read/write to /etc/syconfig/authconfig for PAM setup information

* Tue Aug 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- don't set "shadow" or "md5" for authentication with pam_unix, they're
  not needed (remove for clarity)
- add an authInfoCopy() routine to authinfo.c

* Mon Aug 28 2000 Nalin Dahyabhai <nalin@redhat.com>
- edit /etc/openldap/ldap.conf in addition to /etc/ldap.conf

* Thu Aug 24 2000 Erik Troan <ewt@redhat.com>
- updated it and es translations

* Sun Aug 20 2000 Matt Wilson <msw@redhat.com>
- new translations

* Wed Aug  9 2000 Nalin Dahyabhai <nalin@redhat.com>
- merge in new translations

* Tue Aug  8 2000 Nalin Dahyabhai <nalin@redhat.com>
- add better error reporting for when Bill runs this on a read-only filesystem

* Fri Aug  4 2000 Nalin Dahyabhai <nalin@redhat.com>
- change nss order from (hesiod,ldap,nis) to (nis,ldap,hesiod) in case shadow
  is in use
- kick nscd when we quit if it's running (and obey --nostart)

* Mon Jul 31 2000 Nalin Dahyabhai <nalin@redhat.com>
- silently support the broken_shadow and bigcrypt flags for pam_unix
- only shut down ypbind if /var/run/ypbind exists

* Thu Jul 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- break some translations again

* Wed Jul 26 2000 Matt Wilson <msw@redhat.com>
- new translations for de fr it es

* Fri Jul 21 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix bug parsing NIS server names when there aren't any

* Thu Jul 13 2000 Nalin Dahyabhai <nalin@redhat.com>
- also modify the services, protocols, and automount in nsswitch.conf
- add netgroups, too (#13824)

* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- add --disable options
- try to not mess with ypbind if it isn't installed

* Tue Jun 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak chkconfig magic for ypbind to work better
- turn on portmap when ypbind is enabled

* Mon Jun 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- only do chkconfig magic on ypbind if the ypbind init script exists

* Tue Jun 13 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix multiple-blank-line problem
- verify that NISDOMAIN is recorded properly in /etc/sysconfig/network

* Sat Jun 10 2000 Nalin Dahyabhai <nalin@redhat.com>
- add calls to pam_limits in shared session stack

* Wed Jun  7 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix multiple realms section bug
- close all files we open
- bail on errors, even when we can see the file
- use RPM_OPT_FLAGS
- support multiple NIS servers
- warn if needed files aren't there

* Mon Jun  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix for false-matching beginnings of realm subsections
- FHS fixes

* Thu Jun  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- move default system-auth configuration to pam package

* Wed May 31 2000 Nalin Dahyabhai <nalin@redhat.com>
- add default system-auth configuration

* Tue May 30 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix the uncommented comment problem
- pam_krb5 doesn't provide account management
- base DN can have spaces in it
- use pam_krb5afs for krb5 if /afs is readable
- add the tokens flag to pam_krb5afs
- break (user info and auth setup) into two screens

* Fri May 26 2000 Nalin Dahyabhai <nalin@redhat.com>
- finish LDAP support
- add Kerberos 5 support
- add Hesiod support
- migrate PAM config file logic to new method

* Wed Mar 08 2000 Cristian Gafton <gafton@redhat.com>
- rebuild for release

* Wed Feb 16 2000 Preston Brown <pbrown@redhat.com>
- disable LDAP, update man page.

* Thu Feb 03 2000 Preston Brown <pbrown@redhat.com>
- beginning of /etc/pam.d writing, better man page, broadcast on by default.
- strip man page.

* Tue Jan 11 2000 Preston Brown <pbrown@redhat.com>
- support for LDAP authentication added.

* Tue Sep 21 1999 Matt Wilson <msw@redhat.com>
- updated man page

* Mon Sep 20 1999 Matt Wilson <msw@redhat.com>
- set up shadowed /etc/group

* Mon Aug  2 1999 Matt Wilson <msw@redhat.com>
- rebuilt against newt 0.50

* Mon Apr 19 1999 Cristian Gafton <gafton@redhat.com>
- release for Red Hat Linux 6.0

* Thu Apr 01 1999 Preston Brown <pbrown@redhat.com>
- don't report errors about NIS fields not being filled in if not enabled

* Fri Mar 26 1999 Preston Brown <pbrown@redhat.com>
- fix typo
- change domainname at nis start and stop

* Tue Mar 23 1999 Preston Brown <pbrown@redhat.com>
- fixed man page

* Wed Mar 17 1999 Matt Wilson <msw@redhat.com>
- fixed rewriting /etc/yp.conf
- restarts ypbind so that new changes take effect

* Mon Mar 15 1999 Matt Wilson <msw@redhat.com>
- just make the NIS part of configuration grayed out if NIS is not installed

* Tue Mar 09 1999 Preston Brown <pbrown@redhat.com>
- static buffer sizes increased.

* Tue Mar  9 1999 Matt Wilson <msw@redhat.com>
- removed build opts because of problems on alpha

* Mon Feb  8 1999 Matt Wilson <msw@redhat.com>
- Don't rewrite ypbind.conf if you're not configuring NIS

* Mon Feb  8 1999 Matt Wilson <msw@redhat.com>
- Don't configure NIS if /etc/ypbind.conf does not exist.

* Sat Feb  6 1999 Matt Wilson <msw@redhat.com>
- changed "/sbin/chkconfig --add ypbind" to
  "/sbin/chkconfig --level 345 ypbind on"
- added checks for null nis domains and servers if nis is enabled or if
  not using broadcast.
- added newt entry filter for spaces in domains

* Sat Feb  6 1999 Matt Wilson <msw@redhat.com>
- changed command line options to match user interface
- added --help

* Thu Feb  4 1999 Matt Wilson <msw@redhat.com>
- Rewrote UI to handle geometry management properly
- MD5 passwords do not require shadow passwords, so made them independent

* Wed Feb 03 1999 Preston Brown <pbrown@redhat.com>
- initial spec file
