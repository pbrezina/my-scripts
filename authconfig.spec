Summary: Text-mode tool for setting up NIS and shadow passwords
Name: authconfig
%define version	1.2
Version: %{version}
Release: 4
Copyright: GPL
ExclusiveOS: Linux
Group: Utilities/System
BuildRoot: /var/tmp/%{name}-root
Source: %{name}-%{version}.tar.gz

%description 
This is a terminal mode program for setting up Network Information
Service (NIS) and shadow (more secure) passwords on your system.
Authconfig configures the system to automatically turn on NIS at
system startup as well.

%prep
%setup -q

%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
make INSTROOT=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root)/usr/sbin/authconfig
%attr(-,root,root)/usr/man/man8/authconfig.8
#%attr(-,root,root)/usr/share/locale/*/LC_MESSAGES/authconfig.mo

%changelog
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
