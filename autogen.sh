set -x -e
automake-1.5 -a
aclocal-1.5
gettextize --intl
intltoolize
autoconf-2.53
