Summary: Text-mode tool for setting up NIS and shadow passwords
Name: authconfig
%define version	1.0
Version: %{version}
Release: 1
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
* Wed Feb 03 1999 Preston Brown <pbrown@redhat.com>
- initial spec file
