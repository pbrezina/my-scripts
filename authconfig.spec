Summary: Text-mode tool for setting up NIS and shadow passwords.
Name: authconfig
Version: 4.0.8
Release: 1
License: GPL
ExclusiveOS: Linux
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-root
Source: %{name}-%{version}.tar.gz
Requires: glibc >= 2.1, pam >= 0.72, glib

%description 
Authconfig is a terminal mode program for setting up Network
Information Service (NIS) and shadow (more secure) passwords
on your system. Authconfig also configures the system to
automatically turn on NIS at system startup.

%prep
%setup -q

%build
make

%install
%{makeinstall}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_sbindir}/authconfig
%{_mandir}/man8/*
#%attr(-,root,root)%{_datadir}/locale/*/LC_MESSAGES/authconfig.mo

%changelog
* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- add --disable options

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
