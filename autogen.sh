set -x
intltoolize -f -c
autoreconf --force --install
VERSION=`sed '/AC_INIT/ !d; s/^.*,//; s/).*$//' configure.in`
sed s/@PACKAGE_VERSION@/$VERSION/ authconfig.spec.in > authconfig.spec
test -x mkinstalldirs || cp /usr/share/gettext/mkinstalldirs .
