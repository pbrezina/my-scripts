set -x
gettextize --intl -f
autoheader
automake
libtoolize -f -c
aclocal
intltoolize
autoconf
