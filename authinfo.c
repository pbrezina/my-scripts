 /*
  * Authconfig - client authentication configuration program
  * Copyright (c) 1999-2001 Red Hat, Inc.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  *
  */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <libgen.h>
#include <libintl.h>
#include <locale.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shvar.h"
#include "authinfo.h"
#include "dnsclient.h"

#ifdef LOCAL_POLICIES
#include "localpol.h"
#endif

#define LOGIC_REQUIRED		"required"
#define LOGIC_REQUISITE		"requisite"
#define LOGIC_SUFFICIENT	"sufficient"
#define LOGIC_OPTIONAL		"optional"
#define LOGIC_IGNORE_UNKNOWN	"[default=ok user_unknown=ignore service_err=ignore system_err=ignore]"

/* Snip off line terminators and final whitespace from a passed-in string. */
static void
snipString(char *string)
{
	char *p;
	p = strchr(string, '\r');
	if (p != NULL) {
		*p = '\0';
	}
	p = strchr(string, '\n');
	if (p != NULL) {
		*p = '\0';
	}
	p = string + strlen(string);
	while ((p > string) && isspace(p[-1])) {
		*p = '\0';
		p--;
	}
}

/* Read hesiod setup.  Luckily, /etc/hesiod.conf is simple enough that shvar
 * can read it just fine. */
gboolean
authInfoReadHesiod(struct authInfoType *info)
{
	shvarFile *sv = NULL;
	char *tmp = NULL;

	/* Open the file.  Bail if it's not there. */
	sv = svNewFile(SYSCONFDIR "/hesiod.conf");
	if (sv == NULL) {
		return FALSE;
	}

	/* Read the LHS. */
	tmp = svGetValue(sv, "lhs");
	if (tmp != NULL) {
		info->hesiodLHS = g_strdup(tmp);
		free(tmp);
		snipString(info->hesiodLHS);
	}

	/* Read the RHS. */
	tmp = svGetValue(sv, "rhs");
	if (tmp != NULL) {
		info->hesiodRHS = g_strdup(tmp);
		free(tmp);
		snipString(info->hesiodRHS);
	}

	/* Close the file, we're done. */
	svCloseFile(sv);
	return TRUE;
}

/* Read SMB setup from /etc/pam_smb.conf. */
gboolean
authInfoReadSMB(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p;

	/* Open the file.  Bail if it's not there or there's some problem
	 * reading it. */
	fp = fopen(SYSCONFDIR "/pam_smb.conf", "r");
	if (fp == NULL) {
		return FALSE;
	}

	/* Read three lines.  The first is the workgroup, and subsequent
	 * lines are the PDC and BDC, respectively. */
	if (fgets(buf, sizeof(buf), fp) != NULL) {
		snipString(buf);
		info->smbWorkgroup = g_strdup(buf);
	}
	if (fgets(buf, sizeof(buf), fp) != NULL) {
		snipString(buf);
		info->smbServers = g_strdup(buf);
	}

	/* There are only supposed to be three lines, right?  But there
	 * might be more, so just go with it. */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		snipString(buf);
		if (strlen(buf) > 0) {
			p = info->smbServers;
			if (strlen(p) > 0) {
				info->smbServers = g_strconcat(p, ",",
							       buf, NULL);
			} else {
				info->smbServers = g_strdup(buf);
			}
			g_free(p);
		}
	}

	fclose(fp);

	return TRUE;
}

/* Read NIS setup from /etc/yp.conf. */
gboolean
authInfoReadNIS(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p, *q;

	/* Open the file.  Bail if it's not there. */
	fp = fopen(SYSCONFDIR "/yp.conf", "r");
	if (fp == NULL) {
		return FALSE;
	}

	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		snipString(buf);

		/* Skip initial whitespace. */
		for (p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* Is it a "ypserver" statement?  If so, extract the server. */
		if (strncmp("ypserver", p, 8) == 0) {
			/* Skip intervening whitespace. */
			for (p += 8; (isspace(*p) && (*p != '\0')); p++);

			/* Save the server's name. */
			if (*p != '\0') {
				if (info->nisServer != NULL) {
					/* What?  More than one ypserver?  Okay,
					 * append it to the existing string so
					 * that the single entry field is enough
					 * to edit it. */
					char *tmp = info->nisServer;
					info->nisServer = g_strdup_printf("%s,%s", tmp, p);
					g_free(tmp);
				} else {
					/* The easy case -- save the string. */
					info->nisServer = g_strdup(p);
				}
			}

			continue;
		}

		/* It had better be a "domain" statement, because the man page
		 * for this file states that this is all there is. */
		if (strncmp("domain", p, 6) == 0) {
			/* Skip intervening whitespace. */
			for (p += 6; (isspace(*p) && (*p != '\0')); p++);

			/* Save the domain's name.  To do that, find its end. */
			for (q = p; (!isspace(*q) && (*q != '\0')); q++);
			if (*p != '\0') {
				info->nisDomain = g_strndup(p, q - p);
			}

			/* Skip over some more whitespace. */
			for (p = q; (isspace(*p) && (*p != '\0')); p++);

			/* Is it "server"?  If not, assume "broadcast". */
			if (strncmp(p, "server", 6) == 0) {
				for (p += 6; (isspace(*p) && (*p != '\0')); p++);
				if (*p != '\0') {
					if (info->nisServer != NULL) {
						/* More servers than you can
						 * shake a stick at! */
						char *tmp = info->nisServer;
						info->nisServer = g_strdup_printf("%s,%s", p, tmp);
						g_free(tmp);
					} else {
						/* Save the server name. */
						info->nisServer = g_strdup(p);
					}
				}
			}

			continue;
		}
	}

	fclose(fp);
	return TRUE;
}

/* Read LDAP setup from /etc/ldap.conf. */
gboolean
authInfoReadLDAP(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p;

	/* Open the file.  Bail if it's not there. */
	fp = fopen(SYSCONFDIR "/ldap.conf", "r");
	if (fp == NULL) {
		return FALSE;
	}

	memset(buf, '\0', sizeof(buf));
	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while ((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for (p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* Is it a "base" statement? */
		if (strncmp("base", p, 4) == 0) {
			/* Skip intervening whitespace. */
			for (p += 4; (isspace(*p) && (*p != '\0')); p++);

			/* Save the base DN. */
			if (*p != '\0') {
				info->ldapBaseDN = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Is it a "host" statement? */
		if (strncmp("host", p, 4) == 0) {
			/* Skip intervening whitespace. */
			for (p += 4; (isspace(*p) && (*p != '\0')); p++);

			/* Save the host name or IP. */
			if (*p != '\0') {
				info->ldapServer = g_strdup(p);
				for (p = info->ldapServer; *p != '\0'; p++) {
					if (isspace(*p)) {
						if ((p > info->ldapServer) &&
						   (p[-1] == ',')) {
							memmove(p, p + 1,
								strlen(p));
							p--;
						} else {
							*p = ',';
						}
					}
				}
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Is it a "ssl" statement? */
		if (strncmp("ssl", p, 3) == 0) {
			/* Skip intervening whitespace. */
			for (p += 3; (isspace(*p) && (*p != '\0')); p++);

			info->enableLDAPS = (strncmp(p, "start_tls", 9) == 0);

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* We'll pull MD5/DES crypt ("pam_password") from the config
		 * file, or from the pam_unix PAM config lines. */
		memset(buf, '\0', sizeof(buf));
	}

	fclose(fp);
	return TRUE;
}

/* Read Kerberos setup from /etc/krb5.conf. */
gboolean
authInfoReadKerberos(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p, *q;
	char *section = NULL;
	char *subsection = NULL;

	fp = fopen(SYSCONFDIR "/krb5.conf", "r");
	if (fp == NULL) {
		return FALSE;
	}

	memset(buf, '\0', sizeof(buf));

	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while ((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for (p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* If it's a new section, note which one we're "in". */
		if (p[0] == '[') {
			p++;
			for (q = p; ((*q != ']') && (*q != '\0')); q++);

			if (section != NULL) {
				g_free(section);
			}
			if (subsection != NULL) {
				g_free(subsection);
				subsection = NULL;
			}
			if (q - p > 0)  {
				section = g_strndup(p, q - p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the default realm setting. */
		if (section != NULL)
		if (strcmp(section, "libdefaults") == 0)
		if (strncmp(p, "default_realm", 13) == 0) {
			/* Skip intervening whitespace and the equal sign. */
			for (p += 13;
			    ((isspace(*p) || (*p == '=')) && (*p != '\0'));
			    p++);

			/* Save the default realm. */
			if (*p != '\0') {
				info->kerberosRealm = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the section about the current realm. */
		if (section != NULL)
		if (strcmp(section, "realms") == 0)
		if (subsection == NULL) {
			/* Read the name of the realm. */
			for (q = p; (!isspace(*q) && (*q != '\0')); q++);

			if (q - p > 0)  {
				subsection = g_strndup(p, q - p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the end of a realm section. */
		if (section != NULL)
		if (strcmp(section, "realms") == 0)
		if (subsection != NULL)
		if (strncmp(p, "}", 1) == 0) {
			if (subsection != NULL) {
				g_free(subsection);
				subsection = NULL;
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Values within the current realm. */
		if (section != NULL)
		if (strcmp(section, "realms") == 0)
		if (subsection != NULL)
		if (info->kerberosRealm != NULL)
		if (strcmp(subsection, info->kerberosRealm) == 0) {
			char **target = NULL, *tmp;

			/* See if this is a key we care about. */
			if (strncmp(p, "kdc", 3) == 0) {
				target = &info->kerberosKDC;
				p += 3;
			}
			if (strncmp(p, "admin_server", 12) == 0) {
				target = &info->kerberosAdminServer;
				p += 12;
			}
			if (target == NULL) {
				memset(buf, '\0', sizeof(buf));
				continue;
			}

			/* Skip over the variable and the equal sign. */
			while ((isspace(*p) || (*p == '=')) && (*p != '\0')) p++;

			/* Append if we need to, else make a fresh string. */
			if ((*target != NULL) && (*p != '\0')) {
				tmp = g_malloc0(strlen(p) + strlen(*target) + 2);
				sprintf(tmp, "%s,%s", *target, p);
				g_free(*target);
				*target = tmp;
			}
			if ((*target == NULL) && (*p != '\0')) {
				*target = g_strdup(p);
			}
			memset(buf, '\0', sizeof(buf));
			continue;
		}

		memset(buf, '\0', sizeof(buf));
	}

	fclose(fp);
	return TRUE;
}

/* Read NSS setup from /etc/nsswitch.conf. */
gboolean
authInfoReadNSS(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p;
	char *nss_config = NULL;

	/* Read NIS setup. */
	fp = fopen(SYSCONFDIR "/nsswitch.conf", "r");
	if (fp == NULL) {
		return FALSE;
	}

	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while ((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for (p = buf; (isspace(*p) && (*p != '\0')); p++);

		if (strncmp("passwd:", buf, 7) == 0) {
			/* Skip the keyword and whitespace. */
			for (p += 7; (isspace(*p) && (*p != '\0')); p++);
			if (*p != '\0') {
				nss_config = g_strdup(p);
			}
		}
	}

	if (nss_config != NULL) {
		info->enableDB = (strstr(nss_config, "db") != NULL);
		info->enableHesiod = (strstr(nss_config, "hesiod") != NULL);
		info->enableLDAP = (strstr(nss_config, "ldap") != NULL);
		/* Don't be fooled by "nisplus". */
		for (p = nss_config; strstr(p, "nis") != NULL; p++) {
			info->enableNIS = ((strstr(p, "nis") != NULL) &&
					   ((strstr(p, "nis"))[3] != 'p'));
			if (info->enableNIS) {
				break;
			}
		}
		info->enableNIS3 = (strstr(nss_config, "nisplus") != NULL);
#ifdef EXPERIMENTAL
		info->enableOdbcbind = (strstr(nss_config, "odbcbind") != NULL);
		info->enableWinbind = (strstr(nss_config, "winbind") != NULL);
#endif
	}

	fclose(fp);
	return TRUE;
}

/* Read whether or not caching is enabled. */
gboolean
authInfoReadCache(struct authInfoType *authInfo)
{
	pid_t childpid;
	int status;
	authInfo->enableCache = FALSE;
	childpid = fork();
	if (childpid != 0) {
		/* parent */
		if ((waitpid(childpid, &status, 0) == childpid) &&
		   WIFEXITED(status) &&
		   (WEXITSTATUS(status) == 0)) {
			authInfo->enableCache = TRUE;
		}
	} else {
		/* child */
		char *args[] = {
			"chkconfig",
			"nscd",
			NULL,
		};
		execvp("/sbin/chkconfig", args);
		exit(1);
	}
	return TRUE;
}

/* Read hints from the PAM control file. */
gboolean
authInfoReadPAM(struct authInfoType *authInfo)
{
	char ibuf[LINE_MAX];
	char module[PATH_MAX];
	char flags[PATH_MAX];
	char *p, *q, *stack;
	FILE *fp;
	struct stat st;
	shvarFile *sv = NULL;
	char *tmp = NULL;

	fp = fopen(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, "r");
	if (fp == NULL) {
		return FALSE;
	}

	while (fgets(ibuf, sizeof(ibuf), fp) != NULL) {
		memset(module, '\0', sizeof(module));
		memset(flags, '\0', sizeof(flags));
		snipString(ibuf);

		p = ibuf;
		for (q = p; !isspace(*q) && (*q != '\0'); q++); /* stack */
		stack = p;
		if ((strncmp(stack, "auth", 4) != 0) &&
		   (strncmp(stack, "account", 7) != 0)) {
			continue;
		}

		for (p = q; isspace(*p) && (*p != '\0'); p++);
		for (q = p; !isspace(*q) && (*q != '\0'); q++); /* control */

		for (p = q; isspace(*p) && (*p != '\0'); p++);
		for (q = p; !isspace(*q) && (*q != '\0'); q++); /* module */
		if (q - p < sizeof(module)) {
			strncpy(module, p, q - p);
#ifdef EXPERIMENTAL
			if (strstr(module, "pam_afs")) {
				authInfo->enableAFS = TRUE;
				continue;
			}
			if (strstr(module, "pam_afs.krb")) {
				authInfo->enableAFSKerberos = TRUE;
				continue;
			}
#endif
			if (strstr(module, "pam_krb5")) {
				authInfo->enableKerberos = TRUE;
				continue;
			}
			if (strstr(module, "pam_ldap")) {
				authInfo->enableLDAPAuth = TRUE;
				continue;
			}
#ifdef EXPERIMENTAL
			if (strstr(module, "pam_otp")) {
				authInfo->enableOTP = TRUE;
				continue;
			}
#endif
			if (strstr(module, "pam_smb")) {
				authInfo->enableSMB = TRUE;
				continue;
			}
#ifdef EXPERIMENTAL
			if (strstr(module, "pam_winbind")) {
				authInfo->enableWinbindAuth = TRUE;
				continue;
			}
#endif
#ifdef LOCAL_POLICIES
			if (strstr(module, "pam_stack")) {
				authInfo->enableLocal = TRUE;
				continue;
			}
#endif
		}

		for (p = q; isspace(*p) && (*p != '\0'); p++);
		for (q = p; !isspace(*q) && (*q != '\0'); q++); /* flags */
		if (q - p < sizeof(module)) {
			if (strncmp(stack, "auth", 4) == 0)
			if (strstr(module, "pam_unix") ||
			   strstr(module, "pam_pwdb")) {
				authInfo->enableMD5 =
					(strstr(p, "md5") != NULL);
				authInfo->enableShadow =
					stat("/etc/shadow", &st) == 0;
				authInfo->enableBigCrypt =
					(strstr(p, "bigcrypt") != NULL);
			}
			if (strncmp(stack, "account", 7) == 0)
			if (strstr(module, "pam_unix")) {
				authInfo->brokenShadow =
					(strstr(p, "broken_shadow") != NULL);
			}
		}
	}

	fclose(fp);

	/* Read settings from our config file, which override anything we
	 * figure out by examination. */
	if (stat(SYSCONFDIR "/sysconfig/authconfig", &st) == 0) {
		sv = svNewFile(SYSCONFDIR "/sysconfig/authconfig");
	}
	if (sv != NULL) {
		tmp = svGetValue(sv, "USEAFS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableAFS = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableAFS = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEAFSKERBEROS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableAFSKerberos = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableAFSKerberos = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEDB");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDB = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDB = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEDBBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDBbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDBbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEDBIBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDBIbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDBIbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEEPS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableEPS = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableEPS = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEHESIOD");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableHesiod = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableHesiod = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEHESIODBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableHesiodbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableHesiodbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEKERBEROS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableKerberos = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableKerberos = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USELDAP");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAP = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAP = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USELDAPAUTH");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAPAuth = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAPAuth = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USELDAPBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAPbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAPbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEMD5");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableMD5 = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableMD5 = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USENIS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableNIS = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableNIS = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USENISPLUS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableNIS3 = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableNIS3 = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEODBCBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableOdbcbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableOdbcbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEOTP");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableOTP = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableOTP = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USESHADOW");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableShadow = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableShadow = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USESMBAUTH");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableSMB = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableSMB = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEWINBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableWinbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableWinbind = FALSE;
			}
			free(tmp);
		}
		tmp = svGetValue(sv, "USEWINBINDAUTH");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableWinbindAuth = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableWinbindAuth = FALSE;
			}
			free(tmp);
		}
		svCloseFile(sv);
		sv = NULL;
	}

	return TRUE;
}

/* Read hints from the PAM control file. */
gboolean
authInfoReadNetwork(struct authInfoType *authInfo)
{
	shvarFile *sv = NULL;
	char *tmp = NULL;

	sv = svNewFile(SYSCONFDIR "/sysconfig/network");
	if (sv == NULL) {
		return FALSE;
	}

	if ((tmp = svGetValue(sv, "NISDOMAIN")) != NULL) {
		if (authInfo->nisDomain) g_free(authInfo->nisDomain);
		authInfo->nisDomain = g_strdup(tmp);
		free(tmp);
	}

	svCloseFile(sv);

	return TRUE;
}

struct authInfoType *
authInfoRead()
{
	struct authInfoType *ret = NULL;

	ret = g_malloc0(sizeof(struct authInfoType));

	authInfoReadHesiod(ret);
	authInfoReadSMB(ret);
	authInfoReadNIS(ret);
	authInfoReadLDAP(ret);
	authInfoReadKerberos(ret);
	authInfoReadNSS(ret);
	authInfoReadCache(ret);
	authInfoReadPAM(ret);
	authInfoReadNetwork(ret);

	return ret;
}

void
authInfoFree(struct authInfoType *info)
{
}

struct authInfoType *
authInfoCopy(struct authInfoType *info)
{
	struct authInfoType *ret = NULL;

	ret = g_malloc0(sizeof(struct authInfoType));

	*ret = *info;

	ret->hesiodLHS = info->hesiodLHS ? g_strdup(info->hesiodLHS) : NULL;
	ret->hesiodRHS = info->hesiodLHS ? g_strdup(info->hesiodLHS) : NULL;

	ret->ldapServer = info->ldapServer ? g_strdup(info->ldapServer) : NULL;
	ret->ldapBaseDN = info->ldapBaseDN? g_strdup(info->ldapBaseDN) : NULL;

	ret->kerberosRealm =
	info->kerberosRealm ? g_strdup(info->kerberosRealm) : NULL;

	ret->kerberosKDC =
	info->kerberosKDC ? g_strdup(info->kerberosKDC) : NULL;

	ret->kerberosAdminServer =
	info->kerberosAdminServer ? g_strdup(info->kerberosAdminServer) : NULL;

	ret->nisServer = info->nisServer ? g_strdup(info->nisServer) : NULL;
	ret->nisDomain = info->nisDomain ? g_strdup(info->nisDomain) : NULL;

	ret->smbWorkgroup = info->smbWorkgroup ?
			    g_strdup(info->smbWorkgroup) : NULL;
	ret->smbServers = info->smbServers ? g_strdup(info->smbServers) : NULL;

	return ret;
}

gboolean
authInfoWriteCache(struct authInfoType *authInfo)
{
	if (authInfo->enableCache) {
		system("/sbin/chkconfig --add nscd");
		system("/sbin/chkconfig --level 345 nscd on");
	} else {
		system("/sbin/chkconfig --del nscd");
	}
	return TRUE;
}

static gboolean
non_empty(const char *string)
{
	return (string != NULL) && (strlen(string) > 0);
}
static gboolean
is_empty(const char *string)
{
	return (string == NULL) || (strlen(string) == 0);
}

gboolean
authInfoWriteHesiod(struct authInfoType *info)
{
	shvarFile *sv = NULL;

	if ((sv = svNewFile(SYSCONFDIR "/hesiod.conf")) == NULL) {
		sv = svCreateFile(SYSCONFDIR "/hesiod.conf");
	}

	if (sv == NULL) {
		return FALSE;
	}

	if (info->hesiodLHS != NULL) {
		if (strlen(info->hesiodLHS) == 0) {
			g_free(info->hesiodLHS);
			info->hesiodLHS = NULL;
		}
	}
	svSetValue(sv, "lhs", info->hesiodLHS);
	if (info->hesiodRHS != NULL) {
		if (strlen(info->hesiodRHS) == 0) {
			g_free(info->hesiodRHS);
			info->hesiodRHS = NULL;
		}
	}
	svSetValue(sv, "rhs", info->hesiodRHS);

	svWriteFile(sv, 0644);
	svCloseFile(sv);

	return TRUE;
}

/* Write SMB setup to /etc/pam_smb.conf. */
gboolean
authInfoWriteSMB(struct authInfoType *info)
{
	int fd;
	struct flock lock;
	char **v;

	fd = open(SYSCONFDIR "/pam_smb.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if (ftruncate(fd, 0) == -1) {
		return FALSE;
	}

	if (info->smbWorkgroup != NULL) {
		write(fd, info->smbWorkgroup, strlen(info->smbWorkgroup));
	}
	write(fd, "\n", 1);

	if (non_empty(info->smbServers)) {
		v = g_strsplit(info->smbServers, ",", 0);
	} else {
		v = NULL;
	}
	if (v && v[0]) {
		write(fd, v[0], strlen(v[0]));
	}
	write(fd, "\n", 1);
	if (v && v[0] && v[1]) {
		write(fd, v[1], strlen(v[1]));
	}
	write(fd, "\n", 1);
	if (v) {
		g_strfreev(v);
	}

	close(fd);

	return TRUE;
}

/* Write NIS setup to /etc/yp.conf. */
gboolean
authInfoWriteNIS(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean written = FALSE;

	fd = open(SYSCONFDIR "/yp.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen(" domain ") + strlen(" broadcast ");
	l += info->nisDomain ? strlen(info->nisDomain) : 0;
	l += info->nisServer ? strlen(info->nisServer) : 0;
	obuf = g_malloc0(st.st_size + 1 + l);

	p = ibuf;
	while (*p != '\0') {
		/* Isolate a single line. */
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* If it's a 'domain' line, insert ours instead. */
		if (strncmp("domain", p, 6) == 0) {
			if (!written)
			if (non_empty(info->nisDomain)) {
				strcat(obuf, "domain ");
				strcat(obuf, info->nisDomain);
				/* Take an empty server name to mean that we
				 * want to use broadcast. */
				if (non_empty(info->nisServer)) {
					strcat(obuf, " server ");
					if (strchr(info->nisServer, ',')) {
						char *q;
						q = strchr(info->nisServer, ',');
						strncat(obuf, info->nisServer,
							q - info->nisServer);
					} else {
						strcat(obuf, info->nisServer);
					}
				} else {
					strcat(obuf, " broadcast");
				}
				strcat(obuf, "\n");

				if (non_empty(info->nisServer))
				if (strchr(info->nisServer, ',')) {
					p = strchr(info->nisServer, ',') + 1;
					while (strchr(p, ',')) {
						char *q;
						q = strchr(p, ',');
						strcat(obuf, "ypserver ");
						strncat(obuf, p, q - p);
						strcat(obuf, "\n");
						p = q + 1;
					}
					strcat(obuf, "ypserver ");
					strcat(obuf, p);
					strcat(obuf, "\n");
				}

				written = TRUE;
			}
		} else

		/* If it's a 'ypserver' line, insert ours instead. */
		if (strncmp("ypserver", p, 8) == 0) {
			if (!written)
			if (is_empty(info->nisDomain))
			if (non_empty(info->nisServer)) {
				char *p = info->nisServer;
				while (strchr(p, ',')) {
					char *q;
					q = strchr(p, ',');
					strcat(obuf, "ypserver ");
					strncat(obuf, p, q - p);
					strcat(obuf, "\n");
					p = q + 1;
				}
				strcat(obuf, "ypserver ");
				strcat(obuf, p);
				strcat(obuf, "\n");
				written = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered a domain line yet... */
	if (!written) {
		if (non_empty(info->nisDomain)) {
			strcat(obuf, "domain ");
			strcat(obuf, info->nisDomain);
			if (non_empty(info->nisServer)) {
				strcat(obuf, " server ");
				strcat(obuf, info->nisServer);
			} else {
				strcat(obuf, " broadcast");
			}
			strcat(obuf, "\n");
		} else {
			if (non_empty(info->nisServer)) {
				strcat(obuf, "ypserver ");
				strcat(obuf, info->nisServer);
				strcat(obuf, "\n");
			}
		}
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	g_free(ibuf);
	g_free(obuf);

	return TRUE;
}

/* Write LDAP setup to an ldap.conf using host and base as keys. */
static gboolean
authInfoWriteLDAP2(struct authInfoType *info, const char *filename,
		   const char *host, const char *base, gboolean writePadl)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wrotebasedn = FALSE, wroteserver = FALSE, wrotessl = FALSE,
		 wrotepass = FALSE;

	fd = open(filename, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen(host) + 2 + strlen(base) + 2;
	l += info->ldapBaseDN ? strlen(info->ldapBaseDN) : 0;
	l += info->ldapServer ? strlen(info->ldapServer) : 0;
	l += strlen("ssl start_tls\n");
	l += strlen("pam_password cryptmd5\n");
	obuf = g_malloc0((st.st_size + 1 + l) * 2);

	p = ibuf;
	while (*p != '\0') {
		/* Isolate a single line. */
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* If it's a 'host' line, insert ours instead. */
		if (strncmp(host, p, 4) == 0) {
			if (!wroteserver)
			if (non_empty(info->ldapServer)) {
				size_t l;
				strcat(obuf, host);
				strcat(obuf, " ");
				l = strlen(obuf);
				strcat(obuf, info->ldapServer);
				while (strrchr(obuf + l, ',')) {
					char *p;
					p = strrchr(obuf + l, ',');
					*p = ' ';
				}
				strcat(obuf, "\n");
				wroteserver = TRUE;
			}
		} else

		/* If it's a 'base' line, insert ours instead. */
		if (strncmp(base, p, 4) == 0) {
			if (!wrotebasedn)
			if (non_empty(info->ldapBaseDN)) {
				strcat(obuf, base);
				strcat(obuf, " ");
				strcat(obuf, info->ldapBaseDN);
				strcat(obuf, "\n");
				wrotebasedn = TRUE;
			}
		} else

		/* If it's an 'ssl' line, insert ours instead. */
		if (writePadl && (strncmp("ssl", p, 3)) == 0) {
			if (!wrotessl) {
				strcat(obuf, "ssl");
				strcat(obuf, " ");
				strcat(obuf,
				       info->enableLDAPS ? "start_tls" : "no");
				strcat(obuf, "\n");
				wrotessl = TRUE;
			}
		} else

		/* If it's a 'pam_password' line, write the correct setting. */
		if (writePadl && strncmp("pam_password", p, 12) == 0) {
			if (!wrotepass) {
				strcat(obuf, "pam_password");
				strcat(obuf, " ");
				strcat(obuf, info->enableMD5 ? "md5" : "crypt");
				strcat(obuf, "\n");
				wrotepass = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered either of the config lines yet... */
	if (!wroteserver) {
		if (non_empty(info->ldapServer)) {
			size_t l;
			strcat(obuf, host);
			strcat(obuf, " ");
			l = strlen(obuf);
			strcat(obuf, info->ldapServer);
			while (strrchr(obuf + l, ',')) {
				char *p;
				p = strrchr(obuf + l, ',');
				*p = ' ';
			}
			strcat(obuf, "\n");
		}
	}
	if (!wrotebasedn) {
		if (non_empty(info->ldapBaseDN)) {
			strcat(obuf, base);
			strcat(obuf, " ");
			strcat(obuf, info->ldapBaseDN);
			strcat(obuf, "\n");
		}
	}
	if (writePadl && !wrotessl) {
		strcat(obuf, "ssl");
		strcat(obuf, " ");
		strcat(obuf, info->enableLDAPS ? "start_tls" : "no");
		strcat(obuf, "\n");
	}
	if (writePadl && !wrotepass) {
		strcat(obuf, "pam_password");
		strcat(obuf, " ");
		strcat(obuf, info->enableMD5 ? "md5" : "crypt");
		wrotepass = TRUE;
		strcat(obuf, "\n");
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	g_free(ibuf);
	g_free(obuf);

	return TRUE;
}

gboolean
authInfoWriteLDAP(struct authInfoType *info)
{
	gboolean ret = TRUE;
	if (ret) {
		ret = authInfoWriteLDAP2(info, SYSCONFDIR "/ldap.conf",
					 "host", "base", TRUE);
	}
	if (ret) {
		/* Ignore errors here. */
		authInfoWriteLDAP2(info, SYSCONFDIR "/openldap/ldap.conf",
				   "HOST", "BASE", FALSE);
	}
	return ret;
}

static void
write_kdc(char *obuf, struct authInfoType *info)
{
	char *p = info->kerberosKDC;
	if (is_empty(p))
		return;
	while (strchr(p, ',')) {
		strcat(obuf, "  kdc = ");
		strncat(obuf, p, strchr(p, ',') - p);
		p = strchr(p, ',') + 1;
		strcat(obuf, "\n");
	}
	strcat(obuf, "  kdc = ");
		strcat(obuf, p);
	strcat(obuf, "\n");
}

static void
write_admin_server(char *obuf, struct authInfoType *info)
{
	char *p = info->kerberosAdminServer;
	if (is_empty(p))
		return;
	while (strchr(p, ',')) {
		strcat(obuf, "  admin_server = ");
		strncat(obuf, p, strchr(p, ',') - p);
		p = strchr(p, ',') + 1;
		strcat(obuf, "\n");
	}
	strcat(obuf, "  admin_server = ");
		strcat(obuf, p);
	strcat(obuf, "\n");
}

static void
write_realm(char *obuf, struct authInfoType *info)
{
	strcat(obuf, " ");
	strcat(obuf, info->kerberosRealm);
	strcat(obuf, " = {\n");
	write_kdc(obuf, info);
	write_admin_server(obuf, info);
	strcat(obuf, " }\n");
	strcat(obuf, "\n");
}

static int
comma_count(const char *string)
{
	int ret = 0;
	for (;string && (*string != '\0'); string++) {
		if (*string == ',') {
			ret++;
		}
	}
	return ret;
}

/* Write Kerberos 5 setup to /etc/krb5.conf, */
gboolean
authInfoWriteKerberos5(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wroterealm = FALSE, wrotekdc = FALSE, wroteadmin = FALSE;
	gboolean wroterealms = FALSE, wrotelibdefaults = FALSE;
	gboolean wrotedefaultrealm = FALSE;
	char *section = NULL, *subsection = NULL;

	fd = open(SYSCONFDIR "/krb5.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen("[libdefaults]\n default_realm = \n\n[realm]\n  = { \n }\n");
	l += info->kerberosRealm ? strlen(info->kerberosRealm) * 2 : 1;
	l += strlen("  kdc = \n\n") * (comma_count(info->kerberosKDC) + 1);
	l += info->kerberosKDC ? strlen(info->kerberosKDC) * 2 : 0;
	l += strlen("  admin_server = \n\n") *
	     (comma_count(info->kerberosAdminServer) + 1);
	l += info->kerberosAdminServer ?
	     strlen(info->kerberosAdminServer) * 2 : 0;
	obuf = g_malloc0(st.st_size + 1 + l);

	p = ibuf;
	while (*p != '\0') {
		/* Isolate a single line. */
		char *l = p;
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* Skip over any whitespace. */
		for (;isspace(*p) && (*p != '\0') && (*p != '\n'); p++);

		/* If this is the "kdc" in our realm, replace it with
		 * the values we now have. */
		if ((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection != NULL) &&
		   (non_empty(info->kerberosRealm)) &&
		   (strcmp(subsection, info->kerberosRealm) == 0) &&
		   (strncmp(p, "kdc", 3) == 0)) {
			if (!wrotekdc)
			if (info->kerberosKDC) {
				write_kdc(obuf, info);
				wrotekdc = TRUE;
			}
			p = q;
			continue;
		}

		/* If this is the "admin_server" in our realm, replace it with
		 * the values we now have. */
		if ((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection != NULL) &&
		   (non_empty(info->kerberosRealm)) &&
		   (strcmp(subsection, info->kerberosRealm) == 0) &&
		   (strncmp(p, "admin_server", 3) == 0)) {
			if (!wroteadmin)
			if (info->kerberosAdminServer) {
				write_admin_server(obuf, info);
				wroteadmin = TRUE;
			}
			p = q;
			continue;
		}

		/* If we're in the realms section, but not in a realm, we'd
		 * better be looking at the beginning of one. */
		if ((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection == NULL)) {
			char *q;
			for (q = p; !isspace(*q) && (*q != '\0'); q++);
			if (subsection) {
				g_free(subsection);
			}
			subsection = g_strndup(p, q - p);
			if (is_empty(subsection)) {
				g_free(subsection);
				subsection = NULL;
			} else {
				/* If this is the section for our realm, mark
				 * that. */
				if (strcmp(subsection,info->kerberosRealm) == 0){
					wroterealm = TRUE;
				}
			}
		}

		/* If it's the end of a subsection, mark that. */
		if ((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
	   	   (subsection != NULL) &&
		   (strncmp(p, "}", 1) == 0)) {
			/* If it's the right section of realms, write out
			 * info we haven't already written. */
	   	   	if (non_empty(info->kerberosRealm) &&
	   	   	   (strcmp(subsection, info->kerberosRealm) == 0)) {
				if (!wrotekdc) {
					write_kdc(obuf, info);
				}
				if (!wroteadmin) {
					write_admin_server(obuf, info);
				}
			}
			if (subsection) {
				g_free(subsection);
			}
			subsection = NULL;
		}

		/* If we're in the libdefaults section, and this is the
		 * default_realm keyword, replace it with ours. */
		if ((section != NULL) &&
		   (strcmp(section, "libdefaults") == 0) &&
		   (strncmp(p, "default_realm", 13) == 0)) {
			if (non_empty(info->kerberosRealm) &&
			   !wrotedefaultrealm) {
				strcat(obuf, " default_realm = ");
				strcat(obuf, info->kerberosRealm);
				strcat(obuf, "\n");
				wrotedefaultrealm = TRUE;
			}
			p = q;
			continue;
		}

		/* If it's the beginning of a section, record its name. */
		if (strncmp("[", p, 1) == 0) {
			char *q;
			p++;
			/* If the previous section was "realms", and we didn't
			 * see ours, write our realm out. */
			if ((section != NULL) &&
			   (strcmp(section, "realms") == 0) &&
			   (non_empty(info->kerberosRealm)) &&
			   !wroterealm) {
				write_realm(obuf, info);
				wroterealm = TRUE;
			}
			/* If the previous section was "libdefaults", and we
			 * didn't see a "default_realm", write it out. */
			if ((section != NULL) &&
			   (strcmp(section, "libdefaults") == 0) &&
			   (non_empty(info->kerberosRealm)) &&
			   !wrotedefaultrealm) {
				strcat(obuf, " default_realm = ");
				strcat(obuf, info->kerberosRealm);
				strcat(obuf, "\n");
				wrotedefaultrealm = TRUE;
			}
			for (q = p; ((*q != ']') && (*q != '\0')); q++);
			if (section) {
				g_free(section);
			}
			section = g_strndup(p, q - p);
			if (strcmp(section, "realms") == 0) {
				wroterealms = TRUE;
			}
			if (strcmp(section, "libdefaults") == 0) {
				wrotelibdefaults = TRUE;
			}
		}

		/* Otherwise, just copy the current line out. */
		strncat(obuf, l, q - l);
		p = q;
	}

	/* If we haven't encountered a libdefaults section yet... */
	if (!wrotelibdefaults && non_empty(info->kerberosRealm)) {
		strcat(obuf, "[libdefaults]\n");
		strcat(obuf, " default_realm = ");
		strcat(obuf, info->kerberosRealm);
		strcat(obuf, "\n\n");
	}

	/* If we haven't encountered a realms section yet... */
	if (!wroterealms && non_empty(info->kerberosRealm)) {
		strcat(obuf, "[realms]\n");
		write_realm(obuf, info);
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	/* Clean up. */
	if (ibuf) {
		g_free(ibuf);
	}
	if (obuf) {
		g_free(obuf);
	}
	if (section) {
		g_free(section);
	}
	if (subsection) {
		g_free(subsection);
	}

	return TRUE;
}

/* Write Kerberos 4 setup to /etc/krb.conf, */
gboolean
authInfoWriteKerberos4(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL;
	char *p, *q;
	int fd, l;
	struct flock lock;
	struct stat st;

	if ((info->kerberosRealm == NULL) || (strlen(info->kerberosRealm) == 0)) {
		return FALSE;
	}

	fd = open(SYSCONFDIR "/krb.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}
	if (fstat(fd, &st) == -1) {
		return FALSE;
	}

	ibuf = g_malloc0(st.st_size + 1);
	if (read(fd, ibuf, st.st_size) != st.st_size) {
		g_free(ibuf);
		return FALSE;
	}

	/* Determine the maximum length of the new file. */
	l = st.st_size + strlen("\n");
	l += strlen(info->kerberosRealm ?: " ");

	l += (strlen(info->kerberosRealm ?: "") + strlen("\t \n")) *
	     (comma_count(info->kerberosKDC) + 1);
	l += info->kerberosKDC ? strlen(info->kerberosKDC) * 2 : 0;

	l += (strlen(info->kerberosRealm ?: "") + strlen("\t admin server\n")) *
	     (comma_count(info->kerberosAdminServer) + 1);
	l += info->kerberosAdminServer ?  strlen(info->kerberosAdminServer) : 0;

	obuf = g_malloc0(l);

	/* Set up the buffer with the parts of the file which pertain to our
	 * realm. */
	sprintf(obuf, "%s\n", info->kerberosRealm ?: "");

	p = info->kerberosKDC;
	if (!is_empty(p)) {
		while (strchr(p, ',')) {
			strcat(obuf, info->kerberosRealm ?: "");
			strcat(obuf, "\t");
			strncat(obuf, p, strchr(p, ',') - p);
			strcat(obuf, "\n");
			p = strchr(p, ',') + 1;
		}
	}
	strcat(obuf, info->kerberosRealm ?: "");
	strcat(obuf, "\t");
	strcat(obuf, p);
	strcat(obuf, "\n");

	p = info->kerberosAdminServer;
	if (!is_empty(p)) {
		while (strchr(p, ',')) {
			strcat(obuf, info->kerberosRealm ?: "");
			strcat(obuf, "\t");
			strncat(obuf, p, strchr(p, ',') - p);
			strcat(obuf, " admin server\n");
			p = strchr(p, ',') + 1;
		}
	}
	strcat(obuf, info->kerberosRealm ?: "");
	strcat(obuf, "\t");
	strcat(obuf, p);
	strcat(obuf, " admin server\n");

	/* Now append lines from the original file which have nothing to do
	 * with our realm. */
	p = strchr(ibuf, '\n');
	if (p != NULL) {
		p++;
		while (strchr(p, '\n')) {
			q = strchr(p, '\n') + 1;
			if (strncmp(info->kerberosRealm ?: "",
				   p,
				   strlen(info->kerberosRealm ?: "")) != 0) {
				strncat(obuf, p, q - p);
			}
			p = q;
		}
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	/* Clean up. */
	if (ibuf) {
		g_free(ibuf);
	}
	if (obuf) {
		g_free(obuf);
	}

	return TRUE;
}

/* Write information to /etc/krb5.conf and /etc/krb.conf. */
gboolean
authInfoWriteKerberos(struct authInfoType *info)
{
	gboolean ret;
	ret = authInfoWriteKerberos5(info);
	if (ret == TRUE) {
		authInfoWriteKerberos4(info);
	}
	return ret;
}

/* Write NSS setup to /etc/nsswitch.conf. */
gboolean
authInfoWriteNSS(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	char normal[LINE_MAX] = "", hosts[LINE_MAX] = "";
	gboolean wrotepasswd = FALSE, wrotegroup = FALSE, wroteshadow = FALSE,
		 wroteservices = FALSE, wroteprotocols = FALSE,
		 wrotenetgroup = FALSE, wroteautomount = FALSE,
		 wrotehosts = FALSE;

	fd = open(SYSCONFDIR "/nsswitch.conf", O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen("passwd:     \n") +
	    strlen("shadow:     \n") +
	    strlen("group:      \n") +
	    strlen("services:   \n") +
	    strlen("protocols:  \n") +
	    strlen("netgroup:   \n") +
	    strlen("automount:  \n") +
	    strlen("hosts:      \n");
	l += strlen(" files nisplus nis") * 8;
	l += strlen(" db") * 8;
	l += strlen(" files") * 8;
	l += strlen(" hesiod") * 8;
	l += strlen(" ldap") * 8;
	l += strlen(" nis") * 8;
	l += strlen(" nisplus") * 8;
	l += strlen(" dns");
	l += strlen(" winbind") * 8;
	l += strlen(" dbbind") * 8;
	l += strlen(" dbibind") * 8;
	l += strlen(" hesiodbind") * 8;
	l += strlen(" ldapbind") * 8;
	l += strlen(" odbcbind") * 8;
	obuf = g_malloc0(st.st_size + 1 + l);

	/* Determine what we want in that file for most of the databases.  If
	 * we're using DB, we're doing it for speed, so put it in first.  Then
	 * comes files.  Then everything else in reverse alphabetic order. */
	if (info->enableDB) strcat(normal, " db");
	strcat(normal, " files");
	if (info->enableWinbind) strcat(normal, " winbind");
	if (info->enableOdbcbind) strcat(normal, " odbcbind");
	if (info->enableNIS3) strcat(normal, " nisplus");
	if (info->enableNIS) strcat(normal, " nis");
	if (info->enableLDAPbind) strcat(normal, " ldapbind");
	if (info->enableLDAP) strcat(normal, " ldap");
	if (info->enableHesiodbind) strcat(normal, " hesiodbind");
	if (info->enableHesiod) strcat(normal, " hesiod");
	if (info->enableDBIbind) strcat(normal, " dbibind");
	if (info->enableDBbind) strcat(normal, " dbbind");
	
	/* Hostnames we treat specially. */
	strcat(hosts, " files");
	if (info->enableNIS3) strcat(hosts, " nisplus");
	if (info->enableNIS) strcat(hosts, " nis");
	strcat(hosts, " dns");

	p = ibuf;
	while (*p != '\0') {
		/* Isolate a single line. */
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* If it's a 'passwd' line, insert ours instead. */
		if (strncmp("passwd:", p, 7) == 0) {
			if (!wrotepasswd) {
				strcat(obuf, "passwd:    ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wrotepasswd = TRUE;
			}
		} else

		/* If it's a 'shadow' line, insert ours instead. */
		if (strncmp("shadow:", p, 7) == 0) {
			if (!wroteshadow) {
				strcat(obuf, "shadow:    ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wroteshadow = TRUE;
			}
		} else

		/* If it's a 'group' line, insert ours instead. */
		if (strncmp("group:", p, 6) == 0) {
			if (!wrotegroup) {
				strcat(obuf, "group:     ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wrotegroup = TRUE;
			}
		} else

		/* If it's a 'services' line, insert ours instead. */
		if (strncmp("services:", p, 9) == 0) {
			if (!wroteservices) {
				strcat(obuf, "services:  ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wroteservices = TRUE;
			}
		} else

		/* If it's a 'protocols' line, insert ours instead. */
		if (strncmp("protocols:", p, 10) == 0) {
			if (!wroteprotocols) {
				strcat(obuf, "protocols: ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wroteprotocols = TRUE;
			}
		} else

		/* If it's a 'netgroup' line, insert ours instead. */
		if (strncmp("netgroup:", p, 9) == 0) {
			if (!wrotenetgroup) {
				strcat(obuf, "netgroup:  ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wrotenetgroup = TRUE;
			}
		} else

		/* If it's a 'automount' line, insert ours instead. */
		if (strncmp("automount:", p, 10) == 0) {
			if (!wroteautomount) {
				strcat(obuf, "automount: ");
				strcat(obuf, normal);
				strcat(obuf, "\n");
				wroteautomount = TRUE;
			}
		} else

		/* If it's a 'hosts' line, insert ours instead. */
		if (strncmp("hosts:", p, 6) == 0) {
			if (!wrotehosts) {
				strcat(obuf, "hosts:     ");
				strcat(obuf, hosts);
				strcat(obuf, "\n");
				wrotehosts = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered any of the config lines yet... */
	if (!wrotepasswd) {
		strcat(obuf, "passwd:    ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wroteshadow) {
		strcat(obuf, "shadow:    ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wrotegroup) {
		strcat(obuf, "group:     ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wroteprotocols) {
		strcat(obuf, "protocols: ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wroteservices) {
		strcat(obuf, "services:  ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wrotenetgroup) {
		strcat(obuf, "netgroup:  ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wroteautomount) {
		strcat(obuf, "automount: ");
		strcat(obuf, normal);
		strcat(obuf, "\n");
	}
	if (!wrotehosts) {
		strcat(obuf, "hosts:     ");
		strcat(obuf, hosts);
		strcat(obuf, "\n");
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	g_free(ibuf);
	g_free(obuf);

	return TRUE;
}

/* Mandatory arguments for the various modules. */
#ifdef LOCAL_POLICIES
static const char *argv_local_all[] = {
	"service=" LOCAL_POLICY_NAME,
	NULL,
};
#endif

static const char *argv_unix_auth[] = {
	"likeauth",
	"nullok",
	NULL,
};
static const char *argv_unix_password[] = {
	"nullok",
	"use_authtok",
	NULL,
};

static const char *argv_afs_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_afs_password[] = {
	/* It looks like current pam_afs (from OpenAFS 1.1.1) doesn't support
	 * "use_authtok", so it'll probably interact badly with pam_cracklib,
	 * but thanks to stack-traversal changes in Linux-PAM 0.75 and higher,
	 * the password-changing should work anyway. */
	"use_first_pass",
	NULL,
};

static const char *argv_cracklib_password[] = {
	"retry=3",
	"type=",
	NULL,
};

static const char *argv_eps_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_eps_password[] = {
	"use_authtok",
	NULL,
};

static const char *argv_krb5_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_krb5_password[] = {
	"use_authtok",
	NULL,
};

static const char *argv_krb5afs_auth[] = {
	"use_first_pass",
	"tokens",
	NULL,
};

static const char *argv_ldap_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_ldap_password[] = {
	"use_authtok",
	NULL,
};

/* This probably won't work straight-off because pam_unix won't give the right
 * challenge, but what the heck. */
static const char *argv_otp_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_smb_auth[] = {
	"use_first_pass",
	"nolocal",
	NULL,
};

static const char *argv_winbind_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_winbind_password[] = {
	"use_authtok",
	NULL,
};

/* Enumerations for PAM control flags and stack names. */
enum pam_function_type {
	auth,
	account,
	session,
	password,
};

/* The list of stacks, module flags, and arguments, if there are any.  Here
 * we put pam_unix first, and the rest in alphabetic order. */
static struct {
	gboolean mandatory;
	enum pam_function_type stack;
	const char *logic;
	const char *name;
	const char **argv;
} standard_pam_modules[] = {
	{TRUE,  auth,		LOGIC_REQUIRED,
	 "env",			NULL},
#ifdef LOCAL_POLICIES
	{FALSE, auth,		LOGIC_REQUIRED,
	 "stack",		argv_local_all},
#endif
	{TRUE,  auth,		LOGIC_SUFFICIENT,
	 "unix",		argv_unix_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "afs",			argv_afs_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "afs.krb",		argv_afs_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "eps_auth",		argv_eps_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "krb5",		argv_krb5_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "krb5afs",		argv_krb5afs_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "ldap",		argv_ldap_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "otp",			argv_otp_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "smb_auth",		argv_smb_auth},
	{FALSE, auth,		LOGIC_SUFFICIENT,
	 "winbind",		argv_winbind_auth},
	{TRUE,  auth,		LOGIC_REQUIRED,	
	 "deny",		NULL},

#ifdef LOCAL_POLICIES
	{FALSE, account,	LOGIC_REQUIRED,	
	 "stack",		argv_local_all},
#endif
	{TRUE,  account, 	LOGIC_REQUIRED,
	 "unix",		NULL},
	{TRUE,  account, 	LOGIC_SUFFICIENT,
	 "localuser",		NULL},
	{FALSE, account,	LOGIC_REQUIRED,
	 "ldap",		NULL},

#ifdef LOCAL_POLICIES
	{FALSE, password,	LOGIC_REQUIRED,
	 "stack",		argv_local_all},
#endif
	{TRUE,  password,	LOGIC_REQUIRED,
	 "cracklib",		argv_cracklib_password},
	{TRUE,  password,	LOGIC_SUFFICIENT,
	 "unix",		argv_unix_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "afs",			argv_afs_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "afs.krb",		argv_afs_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "eps_passwd",		argv_eps_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "krb5",		argv_krb5_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "krb5afs",		argv_krb5_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "ldap",		argv_ldap_password},
	{FALSE, password,	LOGIC_SUFFICIENT,
	 "winbind",		argv_winbind_password},
	{TRUE,  password,	LOGIC_REQUIRED,
	 "deny",		NULL},

#ifdef LOCAL_POLICIES
	{FALSE, session,	LOGIC_REQUIRED,
	 "stack",		argv_local_all},
#endif
	{TRUE,  session,	LOGIC_REQUIRED,
	 "limits",		NULL},
	{TRUE,  session,	LOGIC_REQUIRED,
	 "unix",		NULL},
	{FALSE, session,	LOGIC_OPTIONAL,
	 "afs",			NULL},
	{FALSE, session,	LOGIC_OPTIONAL,
	 "afs.krb",		NULL},
	{FALSE, session,	LOGIC_OPTIONAL,
	 "krb5",		NULL},
	{FALSE, session,	LOGIC_OPTIONAL,
	 "krb5afs",		NULL},
	{FALSE, session,	LOGIC_OPTIONAL,
	 "ldap",		NULL},
};

static void
fmt_standard_pam_module(int i, char *obuf, struct authInfoType *info)
{
	char *stack;
	const char *logic = NULL;
	switch(standard_pam_modules[i].stack) {
		case auth:
			stack = "auth";
			break;
		case account:
			stack = "account";
			break;
		case session:
			stack = "session";
			break;
		case password:
			stack = "password";
			break;
		default:
			stack = NULL;
			break;
	}
	logic = standard_pam_modules[i].logic;
	if (non_empty(stack) && non_empty(logic)) {
		if (strlen(logic) > 0) {
			int j;
			char buf[LINE_MAX];
			memset(buf, '\0', sizeof(buf));
			snprintf(buf, sizeof(buf) - 1,
				 "%-12s%-13s %s/pam_%s.so", stack, logic,
				 AUTH_MODULE_DIR, standard_pam_modules[i].name);
			if (standard_pam_modules[i].argv != NULL) {
				for (j = 0;
				    non_empty(standard_pam_modules[i].argv[j]);
				    j++) {
					strncat(buf, " ",
						sizeof(buf) - 1 - strlen(buf));
					strncat(buf,
						standard_pam_modules[i].argv[j],
						sizeof(buf) - 1 - strlen(buf));
				}
			}
			if (strcmp(standard_pam_modules[i].name, "unix") == 0)
			if (stack != NULL) {
				if (strcmp(stack, "password") == 0) {
					if (info->enableMD5) {
						strncat(buf, " md5",
						sizeof(buf) - 1 - strlen(buf));
					}
					if (info->enableShadow) {
						strncat(buf, " shadow",
						sizeof(buf) - 1 - strlen(buf));
					}
					if (info->enableNIS) {
						strncat(buf, " nis",
						sizeof(buf) - 1 - strlen(buf));
					}
					if (info->enableBigCrypt) {
						strncat(buf, " bigcrypt",
						sizeof(buf) - 1 - strlen(buf));
					}
				}
				if ((strcmp(stack, "account") == 0)) {
					if (info->brokenShadow) {
						strncat(buf, " broken_shadow",
						sizeof(buf) - 1 - strlen(buf));
					}
				}
			}
			strcat(obuf, buf);
		}
		strcat(obuf, "\n");
	}
}

/* Write PAM setup to the control file. */
gboolean authInfoWritePAM(struct authInfoType *authInfo)
{
	int i;
	char *obuf = NULL;
	int fd;
	struct flock lock;
	gboolean have_afs = FALSE;
	shvarFile *sv = NULL;

	fd = open(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	obuf = g_malloc0(LINE_MAX *
		       	 (sizeof(standard_pam_modules) / 
		       	  sizeof(standard_pam_modules[0])));
	strcpy(obuf, "#%PAM-1.0\n");
	strcat(obuf, "# This file is auto-generated.\n");
	strcat(obuf, "# User changes will be destroyed the next time "
		     "authconfig is run.\n");

	have_afs = (access("/afs", R_OK | X_OK) != -1);

	for (i = 0;
	    i < sizeof(standard_pam_modules) / sizeof(standard_pam_modules[0]);
	    i++) {
		if ((i > 0) &&
		   (standard_pam_modules[i].stack !=
		    standard_pam_modules[i - 1].stack)) {
			strcat(obuf, "\n");
		}
		if (standard_pam_modules[i].mandatory ||
		   (authInfo->enableAFS &&
		    (strcmp("afs", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableAFSKerberos &&
		    (strcmp("afs.krb", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableEPS &&
		    (strcmp("eps", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableKerberos && !have_afs &&
		    (strcmp("krb5", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableKerberos && have_afs &&
		    (strcmp("krb5afs", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableLDAPAuth &&
		    (strcmp("ldap", standard_pam_modules[i].name) == 0)) ||
#ifdef LOCAL_POLICIES
		   (authInfo->enableLocal &&
		    (strcmp("stack", standard_pam_modules[i].name) == 0)) ||
#endif
		   (authInfo->enableOTP &&
		    (strcmp("otp", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableSMB &&
		    (strcmp("smb_auth", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableWinbindAuth &&
		    (strcmp("winbind", standard_pam_modules[i].name) == 0))) {
			fmt_standard_pam_module(i, obuf, authInfo);
		}
	}

	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	g_free(obuf);
	close(fd);

	sv = svCreateFile(SYSCONFDIR "/sysconfig/authconfig");
	if (sv != NULL) {
		svSetValue(sv, "USEDB",
			   authInfo->enableDB ? "yes" : "no");
		svSetValue(sv, "USEHESIOD",
			   authInfo->enableHesiod ? "yes" : "no");
		svSetValue(sv, "USELDAP",
			   authInfo->enableLDAP ? "yes" : "no");
		svSetValue(sv, "USENIS",
			   authInfo->enableNIS ? "yes" : "no");
#ifdef EXPERIMENTAL
		/* We don't save these settings yet, because we have no
		 * way to present the user with the option. */
		svSetValue(sv, "USENISPLUS",
			   authInfo->enableNIS3 ? "yes" : "no");
		svSetValue(sv, "USEODBCBIND",
			   authInfo->enableOdbcbind ? "yes" : "no");
		svSetValue(sv, "USEWINBIND",
			   authInfo->enableWinbind ? "yes" : "no");
#endif

#ifdef EXPERIMENTAL
		svSetValue(sv, "USEAFS",
			   authInfo->enableAFS ? "yes" : "no");
		svSetValue(sv, "USEAFSKERBEROS",
			   authInfo->enableAFSKerberos ? "yes" : "no");
		svSetValue(sv, "USEEPS",
			   authInfo->enableEPS ? "yes" : "no");
#endif
		svSetValue(sv, "USEKERBEROS",
			   authInfo->enableKerberos ? "yes" : "no");
		svSetValue(sv, "USELDAPAUTH",
			   authInfo->enableLDAPAuth ? "yes" : "no");
		svSetValue(sv, "USEMD5",
			   authInfo->enableMD5 ? "yes" : "no");
#ifdef EXPERIMENTAL
		svSetValue(sv, "USEOTP",
			   authInfo->enableOTP ? "yes" : "no");
#endif
		svSetValue(sv, "USESHADOW",
			   authInfo->enableShadow ? "yes" : "no");
		svSetValue(sv, "USESMBAUTH",
			   authInfo->enableSMB ? "yes" : "no");
#ifdef EXPERIMENTAL
		svSetValue(sv, "USEWINBINDAUTH",
			   authInfo->enableWinbindAuth ? "yes" : "no");
#endif
		svWriteFile(sv, 0644);
		svCloseFile(sv);
	}

	return TRUE;
}

gboolean
authInfoWriteNetwork(struct authInfoType *info)
{
	shvarFile *sv = NULL;

	if ((sv = svNewFile(SYSCONFDIR "/sysconfig/network")) == NULL) {
		sv = svCreateFile(SYSCONFDIR "/sysconfig/network");
	};
	if (sv == NULL) {
		return FALSE;
	}

	if (info->nisDomain != NULL) {
		if (strlen(info->nisDomain) == 0) {
			g_free(info->nisDomain);
			info->nisDomain = NULL;
		}
	}
	svSetValue(sv, "NISDOMAIN", info->nisDomain);
	svWriteFile(sv, 0644);
	svCloseFile(sv);
	return TRUE;
}

gboolean
authInfoWrite(struct authInfoType *authInfo)
{
	gboolean ret;
	ret = authInfoWriteCache(authInfo);
	if (authInfo->enableHesiod)
		ret = ret && authInfoWriteHesiod(authInfo);
	if (authInfo->enableLDAP)
		ret = ret && authInfoWriteLDAP(authInfo);
	if (authInfo->enableKerberos)
		ret = ret && authInfoWriteKerberos(authInfo);
	if (authInfo->enableNIS)
		ret = ret && authInfoWriteNIS(authInfo);
	if (authInfo->enableSMB)
		ret = ret && authInfoWriteSMB(authInfo);
	ret = ret && authInfoWriteNSS(authInfo);
	ret = ret && authInfoWritePAM(authInfo);
	ret = ret && authInfoWriteNetwork(authInfo);
	return ret;
}

static char *
domain2dn(const char *domain)
{
	char buf[LINE_MAX];
	int i;
	strcpy(buf, "DC=");
	for (i = 0; (domain[i] != '\0') && (strlen(buf) < sizeof(buf) - 1); i++){
		if (domain[i] == '.') {
			strcat(buf, ",DC=");
		} else {
			strncat(buf, domain + i, 1);
		}
	}
	return strdup(buf);
}

static void
terminate_hostname(char *hostname)
{
	if (hostname[strlen(hostname) - 1] == '.'){
		hostname[strlen(hostname) - 1] = '\0';
	}
}

struct authInfoType *
authInfoProbe()
{
	struct authInfoType *ret = NULL;
	char hostname[LINE_MAX];
	struct dns_rr *results = NULL;
	unsigned char query[LINE_MAX], buf[LINE_MAX];
	size_t length;
	char *p;

	ret = g_malloc0(sizeof(struct authInfoType));

	/* get the local host name */
	memset(hostname, '\0', sizeof(hostname));
	gethostname(hostname, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = '\0';

	if (strlen(hostname) == 0) {
		return ret;
	}

	dns_client_init();

	/* first, check for an LDAP server for the local domain */
	results = NULL;
	if ((p = strchr(hostname, '.')) != NULL) {
		snprintf(buf, sizeof(buf), "_ldap._tcp%s", p);
		length = dns_format_query(buf, DNS_C_IN, DNS_T_SRV,
					  query, sizeof(query));
		if (length > 0) {
			int ret;
			ret = res_send(query, length, buf, sizeof(buf));
			if (ret != -1) {
				results = dns_parse_results(buf, ret);
			}
		}
	}

	if (results && (p != NULL)) {
		if ((results->dns_type == DNS_T_SRV) &&
		   (results->dns_rdata.srv.server)) {
			ret->ldapServer = strdup(results->dns_rdata.srv.server);
			terminate_hostname(ret->ldapServer);
			ret->ldapBaseDN = domain2dn(++p);
		}
	}

	/* now, check for a Kerberos realm the local host or domain is in */
	results = NULL;
	snprintf(buf, sizeof(buf), "_kerberos.%s", hostname);
	length = dns_format_query(buf, DNS_C_IN, DNS_T_TXT,
				  query, sizeof(query));
	if (length > 0) {
		int ret;
		ret = res_send(query, length, buf, sizeof(buf));
		if (ret != -1) {
			results = dns_parse_results(buf, ret);
		}
	}
	if ((results == NULL) && ((p = strchr(hostname, '.')) != NULL)) {
		snprintf(buf, sizeof(buf), "_kerberos%s", p);
		length = dns_format_query(buf, DNS_C_IN, DNS_T_TXT,
					  query, sizeof(query));
		if (length > 0) {
			int ret;
			ret = res_send(query, length, buf, sizeof(buf));
			if (ret != -1) {
				results = dns_parse_results(buf, ret);
			}
		}
	}
	if (results != NULL) {
		if ((results->dns_type == DNS_T_TXT) &&
		   (results->dns_rdata.txt.data)) {
			ret->kerberosRealm = strdup(results->dns_rdata.txt.data);
		}
	}

	/* now fetch server information for the realm */
	results = NULL;
	if (ret->kerberosRealm) {
		snprintf(buf, sizeof(buf), "_kerberos._udp.%s",
			 ret->kerberosRealm);
		length = dns_format_query(buf, DNS_C_IN, DNS_T_SRV,
					  query, sizeof(query));
		if (length > 0) {
			int ret;
			ret = res_send(query, length, buf, sizeof(buf));
			if (ret != -1) {
				results = dns_parse_results(buf, ret);
			}
		}
	}

	memset(buf, '\0', sizeof(buf));
	if (results != NULL) {
		if ((results->dns_type == DNS_T_SRV) &&
		   (results->dns_rdata.srv.server != NULL)) {
			snprintf(buf, sizeof(buf), "%s",
				 results->dns_rdata.srv.server);
			terminate_hostname(buf);
			if (results->dns_rdata.srv.port != 0) {
				snprintf(buf + strlen(buf),
					 sizeof(buf) - strlen(buf),
					 ":%d",
					 results->dns_rdata.srv.port);
			}
			ret->kerberosKDC = strdup(buf);
		}
	}

	/* now fetch admin server information for the realm */
	results = NULL;
	if (ret->kerberosRealm) {
		snprintf(buf, sizeof(buf), "_kerberos-adm._udp.%s",
			 ret->kerberosRealm);
		length = dns_format_query(buf, DNS_C_IN, DNS_T_SRV,
					  query, sizeof(query));
		if (length > 0) {
			int ret;
			ret = res_send(query, length, buf, sizeof(buf));
			if (ret != -1) {
				results = dns_parse_results(buf, ret);
			}
		}
	}

	/* use all values */
	memset(buf, '\0', sizeof(buf));
	if (results != NULL) {
		if ((results->dns_type == DNS_T_SRV) &&
		   (results->dns_rdata.srv.server != NULL)) {
			snprintf(buf, sizeof(buf), "%s",
				 results->dns_rdata.srv.server);
			terminate_hostname(buf);
			if (results->dns_rdata.srv.port != 0) {
				snprintf(buf + strlen(buf),
					 sizeof(buf) - strlen(buf),
					 ":%d",
					 results->dns_rdata.srv.port);
			}
			ret->kerberosAdminServer = strdup(buf);
		}
	}

	return ret;
}

gboolean
toggleCachingService(gboolean enableCaching, gboolean nostart)
{
	struct stat st;
	if (!nostart) {
		if (enableCaching) {
			system("/sbin/service nscd restart");
		} else {
			if (stat(PATH_NSCD_PID, &st) == 0) {
				system("/sbin/service nscd stop");
			}
		}
	}
	return TRUE;
}

static gboolean
toggleNisService(gboolean enableNis, char *nisDomain, gboolean nostart)
{
	char *domainStr;
	struct stat st;

	if (enableNis && (nisDomain != NULL) && (strlen(nisDomain) > 0)) {
		domainStr =
		    g_strdup_printf("/bin/domainname %s", nisDomain);
		system(domainStr);
		g_free(domainStr);
		if (stat(PATH_PORTMAP, &st) == 0) {
			system("/sbin/chkconfig --add portmap");
			system("/sbin/chkconfig --level 345 portmap on");
			if (!nostart) {
				system("/sbin/service portmap restart");
			}
		}
		if (stat(PATH_YPBIND, &st) == 0) {
			system("/sbin/chkconfig --add ypbind");
			system("/sbin/chkconfig --level 345 ypbind on");
			if (!nostart) {
				if (stat(PATH_YPBIND_PID, &st) == 0) {
					system
					    ("/sbin/service ypbind restart");
				} else {
					system
					    ("/sbin/service ypbind start");
				}
			}
		}
	} else {
		system("/bin/domainname \"(none)\"");
		if (stat(PATH_YPBIND, &st) == 0) {
			if (!nostart) {
				if (stat(PATH_YPBIND_PID, &st) == 0) {
					system
					    ("/sbin/service ypbind stop");
				}
			}
			system("/sbin/chkconfig --del ypbind");
		}
	}

	return TRUE;
}
static gboolean
toggleShadow(struct authInfoType *authInfo)
{
  /* now, do file manipulation on the password files themselves. */
  if (authInfo->enableShadow) {
    system("/usr/sbin/pwconv");
    system("/usr/sbin/grpconv");
  } else {
    system("/usr/sbin/pwunconv");
    system("/usr/sbin/grpunconv");
  }
  return TRUE;
}

void
authInfoPost(struct authInfoType *authInfo, int nostart)
{
    toggleShadow(authInfo);
    toggleNisService(authInfo->enableNIS, authInfo->nisDomain, nostart);
    toggleCachingService(authInfo->enableCache, nostart);
}

void
authInfoPrint(struct authInfoType *authInfo)
{
    printf("caching is %s\n", authInfo->enableCache ? "enabled" : "disabled");
    printf("nss_files is always enabled\n");
    printf("nss_hesiod is %s\n",
	   authInfo->enableHesiod ? "enabled" : "disabled");
    printf(" hesiod LHS = \"%s\"\n",
	   authInfo->hesiodLHS ? authInfo->hesiodLHS : "");
    printf(" hesiod RHS = \"%s\"\n",
	   authInfo->hesiodRHS ? authInfo->hesiodRHS : "");
    printf("nss_ldap is %s\n",
	   authInfo->enableLDAP ? "enabled" : "disabled");
    printf(" LDAP+TLS is %s\n",
	   authInfo->enableLDAPS ? "enabled" : "disabled");
    printf(" LDAP server = \"%s\"\n",
	   authInfo->ldapServer ? authInfo->ldapServer : "");
    printf(" LDAP base DN = \"%s\"\n",
	   authInfo->ldapBaseDN ? authInfo->ldapBaseDN : "");
    printf("nss_nis is %s\n",
	   authInfo->enableNIS ? "enabled" : "disabled");
    printf(" NIS server = \"%s\"\n",
	   authInfo->nisServer ? authInfo->nisServer : "");
    printf(" NIS domain = \"%s\"\n",
	   authInfo->nisDomain ? authInfo->nisDomain : "");
#ifdef LOCAL_POLICIES
    printf("local policies are %s\n",
	   authInfo->enableLocal ? "enabled" : "disabled");
#endif
    printf("pam_unix is always enabled\n");
    printf(" shadow passwords are %s\n",
	   authInfo->enableShadow ? "enabled" : "disabled");
    printf(" md5 passwords are %s\n",
	   authInfo->enableMD5 ? "enabled" : "disabled");
    printf("pam_krb5 is %s\n",
	   authInfo->enableKerberos ? "enabled" : "disabled");
    printf(" krb5 realm = \"%s\"\n",
	   authInfo->kerberosRealm ?: "");
    printf(" krb5 kdc = \"%s\"\n",
	   authInfo->kerberosKDC ?: "");
    printf(" krb5 admin server = \"%s\"\n",
	   authInfo->kerberosAdminServer ?: "");
    printf("pam_ldap is %s\n",
	   authInfo->enableLDAPAuth ? "enabled" : "disabled");
    printf(" LDAP+TLS is %s\n",
	   authInfo->enableLDAPS ? "enabled" : "disabled");
    printf(" LDAP server = \"%s\"\n",
	   authInfo->ldapServer ?: "");
    printf(" LDAP base DN = \"%s\"\n",
	   authInfo->ldapBaseDN ?: "");
    printf("pam_smb_auth is %s\n",
	   authInfo->enableSMB ? "enabled" : "disabled");
    printf(" SMB workgroup = \"%s\"\n",
	   authInfo->smbWorkgroup ?: "");
    printf(" SMB servers = \"%s\"\n",
	   authInfo->smbServers ?: "");
}
