set -x
gettextize --intl -f
autoheader
automake -a
libtoolize -f -c
aclocal
intltoolize
autoconf
