#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <newt.h>
#include <popt.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#define i18n(String) gettext((String))

static char *progName;

static int getNISConfig(
