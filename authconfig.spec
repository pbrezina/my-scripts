Summary: Text tool for setting and loading a keyboard map
Name: kbdconfig
%define version	1.8.3
Version: %{version}
Release: 4
Copyright: GPL
ExclusiveOS: Linux
Group: Utilities/System
BuildRoot: /var/tmp/kbdconfig-root
Source: kbdconfig-%{version}.tar.gz

%description
This is a terminal mode program for setting the keyboard map for your system.
Keyboard maps are necessary for using non US default keyboards. Kbdconfig
loads the selected keymap before exiting and configures your machine to
use that keymap automatically after rebooting.

%prep
%setup -q

%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
make INSTROOT=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root)/usr/sbin/kbdconfig
%attr(-,root,root)/usr/man/man8/kbdconfig.8
%attr(-,root,root)/usr/share/locale/*/LC_MESSAGES/kbdconfig.mo

%changelog
* Sun Jan 10 1999 Matt Wilson <msw@redhat.com>
- rebuilt against newt 0.40
 
* Tue Dec 15 1998 Jeff Johnson <jbj@redhat.com>
- add ru.po

* Thu Oct 22 1998 Bill Nottingham <notting@redhat.com>
- build for Raw Hide (slang-1.2.2)

* Wed Oct 14 1998 Cristian Gafton <gafton@redhat.com>
- translation updates

* Fri Sep 25 1998 Cristian Gafton <gafton@redhat.com>
- turkish message catalog

* Wed Sep 23 1998 Erik Troan <ewt@redhat.com>
- look in qwertz directory as well

* Wed Sep 23 1998 Jeff Johnson <jbj@redhat.com>
- remove path checks from keyboard map processing.
- add sparc support.

* Sun Aug 02 1998 Erik Troan <ewt@redhat.com>
- added --back
- built against newt 0.30

* Sun Mar 22 1998 Erik Troan <ewt@redhat.com>
- added i18n support
- added --back option
- added man page
- buildrooted spec file

* Mon Jan 12 1998 Erik Troan <ewt@redhat.com>
- added patch to replace alloca() with malloc()

* Tue Nov  4 1997 Michael Fulbrght <msf@redhat.com>
- changed to handle .map and .map.gz files properly
