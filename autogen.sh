set -x
gettextize --intl -f --no-changelog
autoheader
automake-1.5 -a
libtoolize -f -c
aclocal
intltoolize
autoconf
