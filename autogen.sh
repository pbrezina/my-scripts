set -x
gettextize --intl -f --no-changelog
autoheader
aclocal-1.5
automake-1.5 -a
libtoolize -f -c
intltoolize
autoconf
