set -x
glib-gettextize -f -c
touch config.h.in
autoheader
libtoolize -f -c
aclocal
automake -a
intltoolize -f
autoconf
VERSION=`sed '/AC_INIT/ !d; s/^.*,//; s/).*$//' configure.in`
sed s/@PACKAGE_VERSION@/$VERSION/ authconfig.spec.in > authconfig.spec
test -x mkinstalldirs || cp /usr/share/gettext/mkinstalldirs .
#./configure $@ --enable-maintainer-rules
