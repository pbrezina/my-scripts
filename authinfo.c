 /*
  * Authconfig - client authentication configuration program
  * Copyright (c) 1999-2004 Red Hat, Inc.
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

#include "config.h"
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <libgen.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <pty.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>
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
#define LOGIC_IGNORE_UNKNOWN	"[default=bad success=ok user_unknown=ignore]"

struct authInfoPrivate {
	char *oldSmbRealm;
	char *oldSmbServers;
	char *oldKerberosRealm;
	char *oldKerberosKDC;
	char *oldKerberosAdminServer;
};

/* Snip off line terminators and final whitespace from a passed-in string. */
static void
snipString(char *string)
{
	char *p;
        p = strpbrk(string, "\r\n");
        if (p != NULL) {
            *p = '\0';
        }
	p = string + strlen(string);
	while ((p > string) && isspace(p[-1])) {
		*p = '\0';
		p--;
	}
}

/* Check if a string is "empty" or "not empty". */
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
static gboolean
changed(const char *old_value, const char *new_value, gboolean case_sensitive)
{
	if (is_empty(old_value) && non_empty(new_value)) {
		return TRUE;
	}
	if (non_empty(old_value) && is_empty(new_value)) {
		return TRUE;
	}
	if (is_empty(old_value) && is_empty(new_value)) {
		return FALSE;
	}
	if (case_sensitive) {
		return (strcmp(old_value, new_value) != 0);
	} else {
		return (g_ascii_strcasecmp(old_value, new_value) != 0);
	}
}

/* Make a list presentable. */
static void
cleanList(char *list)
{
	char *t, *p;
	if (non_empty(list)) {
		while ((t = strpbrk(list, " \t")) != NULL) {
			*t = ',';
		}
		while ((t = strstr(list, ",,")) != NULL) {
			memmove(t, t + 1, strlen(t));
		}
		p = list + strlen(list);
		while ((p > list) && (p[-1] == ',')) {
			*p = '\0';
			p--;
		}
	}
}

static struct authInfoPrivate *
authInfoPrivateNew(void)
{
	struct authInfoPrivate *ret;
	ret = g_malloc0(sizeof(struct authInfoPrivate));
	ret->oldSmbRealm = NULL;
	ret->oldSmbServers = NULL;
	ret->oldKerberosRealm = NULL;
	ret->oldKerberosKDC = NULL;
	ret->oldKerberosAdminServer = NULL;
	return ret;
}

static struct authInfoPrivate *
authInfoPrivateCopy(struct authInfoPrivate *pvt)
{
	struct authInfoPrivate *ret;
	ret = authInfoPrivateNew();
	if (pvt != NULL) {
		if (non_empty(pvt->oldSmbRealm)) {
			ret->oldSmbRealm = g_strdup(pvt->oldSmbRealm);
		}
		if (non_empty(pvt->oldSmbServers)) {
			ret->oldSmbServers = g_strdup(pvt->oldSmbServers);
		}
		if (non_empty(pvt->oldKerberosRealm)) {
			ret->oldKerberosRealm = g_strdup(pvt->oldKerberosRealm);
		}
		if (non_empty(pvt->oldKerberosKDC)) {
			ret->oldKerberosKDC = g_strdup(pvt->oldKerberosKDC);
		}
		if (non_empty(pvt->oldKerberosAdminServer)) {
			ret->oldKerberosAdminServer =
				g_strdup(pvt->oldKerberosAdminServer);
		}
	}
	return ret;
}

static void
authInfoPrivateFree(struct authInfoPrivate *pvt)
{
	if (pvt != NULL) {
		if (pvt->oldSmbRealm != NULL) {
			g_free(pvt->oldSmbRealm);
		}
		if (pvt->oldSmbServers != NULL) {
			g_free(pvt->oldSmbServers);
		}
		if (pvt->oldKerberosRealm!= NULL) {
			g_free(pvt->oldKerberosRealm);
		}
		if (pvt->oldKerberosKDC != NULL) {
			g_free(pvt->oldKerberosKDC);
		}
		if (pvt->oldKerberosAdminServer != NULL) {
			g_free(pvt->oldKerberosAdminServer);
		}
		g_free(pvt);
	}
}

static void
authInfoPrivateReset(struct authInfoType *info)
{
	struct authInfoPrivate *pvt;
	if (info->pvt != NULL) {
		authInfoPrivateFree(info->pvt);
	}
	pvt = authInfoPrivateNew();
	if (non_empty(info->smbRealm)) {
		pvt->oldSmbRealm = g_strdup(info->smbRealm);
	}
	if (non_empty(info->smbServers)) {
		pvt->oldSmbServers = g_strdup(info->smbServers);
	}
	if (non_empty(info->kerberosRealm)) {
		pvt->oldKerberosRealm = g_strdup(info->kerberosRealm);
	}
	if (non_empty(info->kerberosKDC)) {
		pvt->oldKerberosKDC = g_strdup(info->kerberosKDC);
	}
	if (non_empty(info->kerberosAdminServer)) {
		pvt->oldKerberosAdminServer =
			g_strdup(info->kerberosAdminServer);
	}
	info->pvt = pvt;
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
		g_free(tmp);
		snipString(info->hesiodLHS);
	}

	/* Read the RHS. */
	tmp = svGetValue(sv, "rhs");
	if (tmp != NULL) {
		info->hesiodRHS = g_strdup(tmp);
		g_free(tmp);
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
	char buf[BUFSIZ], *p;

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
	char buf[BUFSIZ], *p, *q;

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
	char buf[BUFSIZ], *p;

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
	char buf[BUFSIZ], *p, *q;
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
				section = NULL;
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

		/* Check for the DNS settings. */
		if (section != NULL)
		if (strcmp(section, "libdefaults") == 0)
		if (strncmp(p, "dns_lookup_kdc", 14) == 0) {
			/* Skip intervening whitespace and the equal sign. */
			for (p += 14;
			    ((isspace(*p) || (*p == '=')) && (*p != '\0'));
			    p++);

			/* Save the value. */
			if (*p != '\0') {
				info->kerberosKDCviaDNS =
					(strncmp(p, "true", 4) == 0);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}
		if (section != NULL)
		if (strcmp(section, "libdefaults") == 0)
		if (strncmp(p, "dns_lookup_realm", 16) == 0) {
			/* Skip intervening whitespace and the equal sign. */
			for (p += 16;
			    ((isspace(*p) || (*p == '=')) && (*p != '\0'));
			    p++);

			/* Save the value. */
			if (*p != '\0') {
				info->kerberosRealmviaDNS =
					(strncmp(p, "true", 4) == 0);
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

/* Check for a string in an nss configuration line. */
static gboolean
authInfoCheckNSS(const char *configuration, const char *candidate)
{
	const char *p;
	char c;
	p = configuration;
	if (strchr(p, ':')) {
		p = strchr(p, ':') + 1;
	}
	while (p != NULL) {
		p = strstr(p, candidate);
		if (p != NULL) {
			c = p[strlen(candidate)];
			switch (c) {
			case '\0':
			case '\r':
			case '\n':
			case '[':
				return TRUE;
			default:
				if (!g_ascii_isalnum(c)) {
					return TRUE;
				}
				break;
			}
			p++;
		}
	}
	return FALSE;
}

/* Read NSS setup from /etc/nsswitch.conf. */
gboolean
authInfoReadNSS(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[BUFSIZ], *p;
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
			for (p += 7; (isspace(*p) && (*p != '\0')); p++) /* */;
			if (*p != '\0') {
				nss_config = g_strdup(p);
			}
		}
	}

	if (nss_config != NULL) {
		info->enableCompat = authInfoCheckNSS(nss_config, "compat");
		info->enableDB = authInfoCheckNSS(nss_config, "db");
		info->enableDirectories = authInfoCheckNSS(nss_config,
							   "directories");
		info->enableHesiod = authInfoCheckNSS(nss_config, "hesiod");
		info->enableLDAP = authInfoCheckNSS(nss_config, "ldap");
		info->enableNIS = authInfoCheckNSS(nss_config, "nis");
		info->enableNIS3 = authInfoCheckNSS(nss_config, "nisplus");
		info->enableWinbind = authInfoCheckNSS(nss_config, "winbind");
		info->enableWINS = authInfoCheckNSS(nss_config, "wins");
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
	char ibuf[BUFSIZ];
	char module[PATH_MAX];
	char args[PATH_MAX];
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
		    (strncmp(stack, "account", 7) != 0) &&
		    (strncmp(stack, "password", 8) != 0) &&
		    (strncmp(stack, "session", 7) != 0)) {
			continue;
		}

		for (p = q; isspace(*p) && (*p != '\0'); p++);
		q = p;
		if (*p == '[') {
			while ((*q != '\0') && (*q != ']')) {
				q++;
			}
		}
		for (; !isspace(*q) && (*q != '\0'); q++); /* control */

		for (p = q; isspace(*p) && (*p != '\0'); p++);
		for (q = p; !isspace(*q) && (*q != '\0'); q++); /* module */
		if (q - p < sizeof(module)) {
			strncpy(module, p, q - p);
			memset(&args, '\0', sizeof(args));
			for (p = q; isspace(*p) && (*p != '\0'); p++);
			for (q = p; (*q != '\n') && (*q != '\0'); q++); /* args */
			if (q - p < sizeof(args)) {
				strncpy(args, p, q - p);
			}
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
			if (strstr(module, "pam_cracklib")) {
				authInfo->enableCracklib = TRUE;
				if (non_empty(args)) {
					authInfo->cracklibArgs = g_strdup(args);
				}
				continue;
			}
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
			if (strstr(module, "pam_passwdqc")) {
				authInfo->enablePasswdQC = TRUE;
				if (non_empty(args)) {
					authInfo->passwdqcArgs = g_strdup(args);
				}
				continue;
			}
			if (strstr(module, "pam_smb")) {
				authInfo->enableSMB = TRUE;
				continue;
			}
			if (strstr(module, "pam_winbind")) {
				authInfo->enableWinbind = TRUE;
				continue;
			}
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
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEAFSKERBEROS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableAFSKerberos = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableAFSKerberos = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEDB");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDB = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDB = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USECRACKLIB");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableCracklib = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableCracklib = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEDBBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDBbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDBbind = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEDBIBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDBIbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDBIbind = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEDIRECTORIES");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableDirectories = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableDirectories = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEEPS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableEPS = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableEPS = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEHESIOD");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableHesiod = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableHesiod = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEHESIODBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableHesiodbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableHesiodbind = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEKERBEROS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableKerberos = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableKerberos = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USELDAP");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAP = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAP = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USELDAPAUTH");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAPAuth = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAPAuth = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USELDAPBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableLDAPbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableLDAPbind = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEMD5");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableMD5 = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableMD5 = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USENIS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableNIS = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableNIS = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USENISPLUS");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableNIS3 = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableNIS3 = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEODBCBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableOdbcbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableOdbcbind = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEOTP");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableOTP = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableOTP = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEPASSWDQC");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enablePasswdQC = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enablePasswdQC = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USESHADOW");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableShadow = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableShadow = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USESMBAUTH");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableSMB = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableSMB = FALSE;
			}
			g_free(tmp);
		}
		tmp = svGetValue(sv, "USEWINBIND");
		if (tmp != NULL) {
			if (strcmp(tmp, "yes") == 0) {
				authInfo->enableWinbind = TRUE;
			}
			if (strcmp(tmp, "no") == 0) {
				authInfo->enableWinbind = FALSE;
			}
			g_free(tmp);
		}
		svCloseFile(sv);
		sv = NULL;
	}

	/* Special handling for pam_cracklib and pam_passwdqc: there can be
	 * only one. */
	if (authInfo->enableCracklib && authInfo->enablePasswdQC) {
		authInfo->enablePasswdQC = FALSE;
	}
	if (!authInfo->enableCracklib && !authInfo->enablePasswdQC) {
		authInfo->enableCracklib = TRUE;
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
		if (authInfo->nisDomain) {
			g_free(authInfo->nisDomain);
		}
		authInfo->nisDomain = g_strdup(tmp);
		g_free(tmp);
	}

	svCloseFile(sv);

	return TRUE;
}

/* Compare two authInfoType structures and return TRUE if they have any
 * meaningful differences. */
static gboolean
string_differs(const char *a, const char *b, gboolean case_sensitive)
{
	if (is_empty(a) && is_empty(b)) {
		return FALSE;
	}
	if (is_empty(a) || is_empty(b)) {
		return TRUE;
	}
	if (case_sensitive) {
		return (strcmp(a, b) != 0) ? TRUE : FALSE;
	} else {
		return (g_ascii_strcasecmp(a, b) != 0) ? TRUE : FALSE;
	}
}
gboolean
authInfoDiffers(struct authInfoType *a, struct authInfoType *b)
{
	return  string_differs(a->hesiodLHS, b->hesiodLHS, FALSE) ||
		string_differs(a->hesiodRHS, b->hesiodRHS, FALSE) ||

		string_differs(a->ldapServer, b->ldapServer, FALSE) ||
		string_differs(a->ldapBaseDN, b->ldapBaseDN, FALSE) ||

		string_differs(a->kerberosRealm, b->kerberosRealm, TRUE) ||
		(a->kerberosRealmviaDNS != b->kerberosRealmviaDNS) ||
		string_differs(a->kerberosKDC, b->kerberosKDC, FALSE) ||
		(a->kerberosKDCviaDNS != b->kerberosKDCviaDNS) ||
		string_differs(a->kerberosAdminServer,
			       b->kerberosAdminServer, FALSE) ||
		string_differs(a->nisServer, b->nisServer, TRUE) ||
		string_differs(a->nisDomain, b->nisDomain, TRUE) ||

		string_differs(a->smbWorkgroup, b->smbWorkgroup, FALSE) ||
		string_differs(a->smbRealm, b->smbRealm, TRUE) ||
		string_differs(a->smbServers, b->smbServers, FALSE) ||
		string_differs(a->smbSecurity, b->smbSecurity, FALSE) ||
		string_differs(a->smbIdmapUid, b->smbIdmapUid, FALSE) ||
		string_differs(a->smbIdmapGid, b->smbIdmapGid, FALSE) ||

		string_differs(a->winbindSeparator,
			       b->winbindSeparator, TRUE) ||
		string_differs(a->winbindTemplateHomedir,
			       b->winbindTemplateHomedir, TRUE) ||
		string_differs(a->winbindTemplatePrimaryGroup,
			       b->winbindTemplatePrimaryGroup, TRUE) ||
		string_differs(a->winbindTemplateShell,
			       b->winbindTemplateShell, TRUE) ||

		(a->winbindUseDefaultDomain != b->winbindUseDefaultDomain) ||
		/* (a->enableCache != b->enableCache) || */

		(a->enableDB != b->enableDB) ||
		(a->enableDirectories != b->enableDirectories) ||
		(a->enableHesiod != b->enableHesiod) ||
		(a->enableLDAP != b->enableLDAP) ||
		(a->enableLDAPS != b->enableLDAPS) ||
		(a->enableNIS != b->enableNIS) ||
		(a->enableNIS3 != b->enableNIS3) ||
		(a->enableDBbind != b->enableDBbind) ||
		(a->enableDBIbind != b->enableDBIbind) ||
		(a->enableHesiodbind != b->enableHesiodbind) ||
		(a->enableLDAPbind != b->enableLDAPbind) ||
		(a->enableOdbcbind != b->enableOdbcbind) ||
		(a->enableWinbind != b->enableWinbind) ||
		(a->enableWINS != b->enableWINS) ||

		(a->enableAFS != b->enableAFS) ||
		(a->enableAFSKerberos != b->enableAFSKerberos) ||
		(a->enableBigCrypt != b->enableBigCrypt) ||
		(a->enableCracklib != b->enableCracklib) ||
		(a->enableEPS != b->enableEPS) ||
		(a->enableKerberos != b->enableKerberos) ||
		(a->enableLDAPAuth != b->enableLDAPAuth) ||
		(a->enableMD5 != b->enableMD5) ||
		(a->enableOTP != b->enableOTP) ||
		(a->enablePasswdQC != b->enablePasswdQC) ||
		(a->enableShadow != b->enableShadow) ||
		(a->enableSMB != b->enableSMB) ||
#ifdef LOCAL_POLICIES
		(a->enableLocal != b->enableLocal) ||
#endif
		(a->brokenShadow != b->brokenShadow) ||

		string_differs(a->joinUser, b->joinUser, TRUE) ||
		string_differs(a->joinPassword, b->joinPassword, TRUE);
}

/* There's some serious strangeness in here, because we get called in two
 * different-but-closely-related scenarios.  The first case is when we're
 * initializing the authInfo structure and we want to fill in defaults with
 * suggestions we "know".  The second case is when the user has just made a
 * change to one field and we need to update another field to somehow
 * compensate for the change. */
void
authInfoUpdate(struct authInfoType *info)
{
	const char *p;
	cleanList(info->smbServers);
	cleanList(info->kerberosKDC);
	cleanList(info->kerberosAdminServer);
	if (non_empty(info->smbSecurity)) {
		if (strcmp(info->smbSecurity, "ads") == 0) {
			/* As of this writing, an ADS implementation always
			 * upper-cases the realm name, even if only internally,
			 * and we need to reflect that in the krb5.conf file. */
			if (non_empty(info->smbRealm)) {
				int i;
				for (i = 0; info->smbRealm[i] != '\0'; i++) {
					info->smbRealm[i] =
						g_ascii_toupper(info->smbRealm[i]);
				}
			}
			/* If we have changed a value, make the related setting
			 * reflect the change. */
			if (info->pvt != NULL) {
				if (changed(info->pvt->oldKerberosRealm,
					    info->kerberosRealm,
					    TRUE)) {
					if (info->smbRealm != NULL) {
						g_free(info->smbRealm);
					}
					info->smbRealm =
						g_strdup(info->kerberosRealm);
				} else
				if (changed(info->pvt->oldSmbRealm,
					    info->smbRealm,
					    FALSE)) {
					if (info->kerberosRealm != NULL) {
						g_free(info->kerberosRealm);
					}
					info->kerberosRealm =
						g_strdup(info->smbRealm);
				}
				if (changed(info->pvt->oldKerberosAdminServer,
					    info->kerberosAdminServer,
					    TRUE) ||
				    changed(info->pvt->oldKerberosKDC,
					    info->kerberosKDC,
					    TRUE)) {
					if (info->smbServers != NULL) {
						g_free(info->smbServers);
					}
					info->smbServers =
						g_strdup_printf("%s,%s",
						info->kerberosAdminServer ?
						info->kerberosAdminServer : "",
						info->kerberosKDC ?
						info->kerberosKDC : "");
				} else
				if (changed(info->pvt->oldSmbServers,
					    info->smbServers,
					    TRUE)) {
					if (info->kerberosKDC != NULL) {
						g_free(info->kerberosKDC);
					}
					if (info->kerberosAdminServer != NULL) {
						g_free(info->kerberosAdminServer);
					}
					p = strchr(info->smbServers, ',');
					if (p != NULL) {
						info->kerberosAdminServer =
							g_strndup(info->smbServers,
								  p - info->smbServers);
						info->kerberosKDC =
							g_strdup(p + 1);
					} else {
						info->kerberosAdminServer =
							g_strdup(info->smbServers);
						info->kerberosKDC =
							g_strdup(info->smbServers);
					}
				}
			}
			/* Override smb.conf realm with krb5.conf realm. */
			if (non_empty(info->kerberosRealm)) {
				if (info->smbRealm != NULL) {
					g_free(info->smbRealm);
				}
				info->smbRealm = g_strdup(info->kerberosRealm);
			}
			/* Default krb5.conf realm to smb.conf realm. */
			if (is_empty(info->kerberosRealm)) {
				if (non_empty(info->smbRealm)) {
					if (info->kerberosRealm != NULL) {
						g_free(info->kerberosRealm);
					}
					info->kerberosRealm = g_strdup(info->smbRealm);
				}
			}
			/* Override smb.conf servers with krb5.conf servers. */
			if (non_empty(info->kerberosAdminServer) ||
			    non_empty(info->kerberosKDC)) {
				if (info->smbServers != NULL) {
					g_free(info->smbServers);
				}
				info->smbServers = g_strdup_printf("%s,%s",
					info->kerberosAdminServer ?
					info->kerberosAdminServer : "",
					info->kerberosKDC ?
					info->kerberosKDC : "");
			}
			/* Default krb5.conf servers with smb.conf servers. */
			if (is_empty(info->kerberosKDC)) {
				if (non_empty(info->smbServers)) {
					if (info->kerberosKDC != NULL) {
						g_free(info->kerberosKDC);
					}
					if (info->kerberosAdminServer != NULL) {
						g_free(info->kerberosAdminServer);
					}
					p = strchr(info->smbServers, ',');
					if (p != NULL) {
						info->kerberosAdminServer =
							g_strndup(info->smbServers,
								  p - info->smbServers);
						info->kerberosKDC =
							g_strdup(p + 1);
					} else {
						info->kerberosAdminServer =
							g_strdup(info->smbServers);
						info->kerberosKDC =
							g_strdup(info->smbServers);
					}
				}
			}
		}
	}
	cleanList(info->smbServers);
	cleanList(info->kerberosKDC);
	cleanList(info->kerberosAdminServer);
	authInfoPrivateReset(info);
}

struct authInfoType *
authInfoRead(void)
{
	struct authInfoType *ret = NULL;

	ret = g_malloc0(sizeof(struct authInfoType));

	authInfoReadHesiod(ret);
	authInfoReadSMB(ret);
	authInfoReadWinbind(ret);
	authInfoReadNIS(ret);
	authInfoReadLDAP(ret);
	authInfoReadKerberos(ret);
	authInfoReadNSS(ret);
	authInfoReadCache(ret);
	authInfoReadPAM(ret);
	authInfoReadNetwork(ret);

	authInfoUpdate(ret);

	return ret;
}

void
authInfoFree(struct authInfoType *info)
{
	if (info) {
		if (info->pvt) {
			authInfoPrivateFree(info->pvt);
		}
		if (info->hesiodLHS) {
			g_free(info->hesiodLHS);
		}
		if (info->hesiodRHS) {
			g_free(info->hesiodRHS);
		}
		if (info->ldapServer) {
			g_free(info->ldapServer);
		}
		if (info->ldapBaseDN) {
			g_free(info->ldapBaseDN);
		}
		if (info->kerberosRealm) {
			g_free(info->kerberosRealm);
		}
		if (info->kerberosKDC) {
			g_free(info->kerberosKDC);
		}
		if (info->kerberosAdminServer) {
			g_free(info->kerberosAdminServer);
		}
		if (info->nisServer) {
			g_free(info->nisServer);
		}
		if (info->nisDomain) {
			g_free(info->nisDomain);
		}
		if (info->smbWorkgroup) {
			g_free(info->smbWorkgroup);
		}
		if (info->smbRealm) {
			g_free(info->smbRealm);
		}
		if (info->smbServers) {
			g_free(info->smbServers);
		}
		if (info->smbSecurity) {
			g_free(info->smbSecurity);
		}
		if (info->smbIdmapUid) {
			g_free(info->smbIdmapUid);
		}
		if (info->smbIdmapGid) {
			g_free(info->smbIdmapGid);
		}
		if (info->winbindSeparator) {
			g_free(info->winbindSeparator);
		}
		if (info->winbindTemplateHomedir) {
			g_free(info->winbindTemplateHomedir);
		}
		if (info->winbindTemplatePrimaryGroup) {
			g_free(info->winbindTemplatePrimaryGroup);
		}
		if (info->winbindTemplateShell) {
			g_free(info->winbindTemplateShell);
		}
		if (info->joinUser) {
			g_free(info->joinUser);
		}
		if (info->joinPassword) {
			g_free(info->joinPassword);
		}
		g_free(info);
	}
}

struct authInfoType *
authInfoCopy(struct authInfoType *info)
{
	struct authInfoType *ret = NULL;

	ret = g_malloc0(sizeof(struct authInfoType));

	*ret = *info;

	ret->hesiodLHS = info->hesiodLHS ? g_strdup(info->hesiodLHS) : NULL;
	ret->hesiodRHS = info->hesiodRHS ? g_strdup(info->hesiodRHS) : NULL;

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
	ret->smbRealm = info->smbRealm ? g_strdup(info->smbRealm) : NULL;
	ret->smbServers = info->smbServers ? g_strdup(info->smbServers) : NULL;
	ret->smbSecurity = info->smbSecurity ? g_strdup(info->smbSecurity) : NULL;
	ret->smbIdmapUid = info->smbIdmapUid ? g_strdup(info->smbIdmapUid) : NULL;
	ret->smbIdmapGid = info->smbIdmapGid ? g_strdup(info->smbIdmapGid) : NULL;

	ret->winbindSeparator = info->winbindSeparator ?
				g_strdup(info->winbindSeparator) : NULL;
	ret->winbindTemplateHomedir = info->winbindTemplateHomedir ?
				g_strdup(info->winbindTemplateHomedir) : NULL;
	ret->winbindTemplatePrimaryGroup = info->winbindTemplatePrimaryGroup ?
			g_strdup(info->winbindTemplatePrimaryGroup) : NULL;
	ret->winbindTemplateShell = info->winbindTemplateShell ?
				g_strdup(info->winbindTemplateShell) : NULL;

	ret->pvt = authInfoPrivateCopy(info->pvt);
	ret->joinUser = NULL;
	ret->joinPassword = NULL;

	ret->cracklibArgs = info->cracklibArgs ?
			    g_strdup(info->cracklibArgs) : NULL;
	ret->passwdqcArgs = info->passwdqcArgs ?
			    g_strdup(info->passwdqcArgs) : NULL;

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
		close(fd);
		return FALSE;
	}

	if (ftruncate(fd, 0) == -1) {
		close(fd);
		return FALSE;
	}

	if (info->smbWorkgroup != NULL) {
		write(fd, info->smbWorkgroup, strlen(info->smbWorkgroup));
	}
	write(fd, "\n", 1);

	if (non_empty(info->smbServers)) {
		/* Convert any spaces in the list to commas for splitting. */
		char *tmp, *p;
		tmp = g_strdup(info->smbServers);
		while ((p = strpbrk(tmp, " \t")) != NULL) {
			*p = ',';
		}
		while ((p = strstr(tmp, ",,")) != NULL) {
			memmove(p, p + 1, strlen(p));
		}
		v = g_strsplit(tmp, ",", 0);
		g_free(tmp);
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
		close(fd);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
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
		} else {
			/* Otherwise, just copy the current line out. */
			strncat(obuf, p, q - p);
		}
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
		close(fd);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
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
		} else {
			/* Otherwise, just copy the current line out. */
			strncat(obuf, p, q - p);
		}
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
write_cryptstyle(char *obuf, struct authInfoType *info)
{
	strcat(obuf, "crypt_style = ");
	if (info->enableMD5) {
		strcat(obuf, "md5");
	} else {
		strcat(obuf, "des");
	}
	strcat(obuf, "\n");
}

/* Write libuser's md5 setting to /etc/libuser.conf, */
gboolean
authInfoWriteLibuser(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wrotecryptstyle = FALSE;
	gboolean wrotedefaults = FALSE;
	char *section = NULL;

	fd = open(SYSCONFDIR "/libuser.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		close(fd);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen("[defaults]\n crypt_style = md5\n\n\n\n");
	obuf = g_malloc0(st.st_size + 1 + l);

	p = ibuf;
	while (*p != '\0') {
		/* Isolate a single line. */
		char *l = p;
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* Skip over any whitespace. */
		for (;isspace(*p) && (*p != '\0') && (*p != '\n'); p++);

		/* If this is the "crypt_style" in the defaults section,
		 * replace it with the values we now have. */
		if ((section != NULL) &&
		    (strcmp(section, "defaults") == 0) &&
		    (strncmp(p, "crypt_style", 11) == 0)) {
			write_cryptstyle(obuf, info);
			wrotecryptstyle = TRUE;
			p = q;
			continue;
		}

		/* If it's the beginning of a section, record its name. */
		if (strncmp("[", p, 1) == 0) {
			char *q;
			p++;
			/* If the previous section was "defaults", and we didn't
			 * see the crypt_style setting , write it out. */
			if ((section != NULL) &&
			    (strcmp(section, "defaults") == 0) &&
			    !wrotecryptstyle) {
				write_cryptstyle(obuf, info);
				wrotecryptstyle = TRUE;
			}
			for (q = p; ((*q != ']') && (*q != '\0')); q++) ;
			if (section) {
				g_free(section);
			}
			section = g_strndup(p, q - p);
			if (strcmp(section, "defaults") == 0) {
				wrotedefaults = TRUE;
			}
		}

		/* Otherwise, just copy the current line out. */
		strncat(obuf, l, q - l);
		p = q;
	}

	/* If we haven't encountered a defaults section yet... */
	if (!wrotedefaults) {
		strcat(obuf, "[defaults]\n");
		write_cryptstyle(obuf, info);
		wrotedefaults = TRUE;
		wrotecryptstyle = TRUE;
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

	return TRUE;
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
static gboolean
authInfoWriteKerberos5(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wroterealm = FALSE, wrotekdc = FALSE, wroteadmin = FALSE;
	gboolean wroterealms = FALSE, wrotelibdefaults = FALSE,
		 wroterealms2 = FALSE, wrotelibdefaults2 = FALSE;
	gboolean wrotedefaultrealm = FALSE, wrotednsrealm = FALSE,
		 wrotednskdc = FALSE;
	char *section = NULL, *subsection = NULL;

	fd = open(SYSCONFDIR "/krb5.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		close(fd);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen("[libdefaults]\n default_realm = \n\n[realm]\n  = { \n }\n");
	l += strlen(" dns_lookup_realm = false\n") * 2;
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
					wrotekdc = TRUE;
				}
				if (!wroteadmin) {
					write_admin_server(obuf, info);
					wroteadmin = TRUE;
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
		if ((section != NULL) &&
		    (strcmp(section, "libdefaults") == 0) &&
		    (strncmp(p, "dns_lookup_realm", 16) == 0)) {
			if (!wrotednsrealm) {
				strcat(obuf, " dns_lookup_realm = ");
				strcat(obuf, info->kerberosRealmviaDNS ?
					     "true" : "false");
				strcat(obuf, "\n");
				wrotednsrealm = TRUE;
			}
			p = q;
			continue;
		}
		if ((section != NULL) &&
		    (strcmp(section, "libdefaults") == 0) &&
		    (strncmp(p, "dns_lookup_kdc", 14) == 0)) {
			if (!wrotednskdc) {
				strcat(obuf, " dns_lookup_kdc = ");
				strcat(obuf, info->kerberosKDCviaDNS ?
					     "true" : "false");
				strcat(obuf, "\n");
				wrotednskdc = TRUE;
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
			if ((section != NULL) &&
			    (strcmp(section, "libdefaults") == 0) &&
			    !wrotednsrealm) {
				strcat(obuf, " dns_lookup_realm = ");
				strcat(obuf, info->kerberosRealmviaDNS ?
					     "true" : "false");
				strcat(obuf, "\n");
				wrotednsrealm = TRUE;
			}
			if ((section != NULL) &&
			    (strcmp(section, "libdefaults") == 0) &&
			    !wrotednskdc) {
				strcat(obuf, " dns_lookup_kdc = ");
				strcat(obuf, info->kerberosKDCviaDNS ?
					     "true" : "false");
				strcat(obuf, "\n");
				wrotednskdc = TRUE;
			}
			for (q = p; ((*q != ']') && (*q != '\0')); q++) /* */;
			if (section) {
				if (strcmp(section, "realms") == 0) {
					wroterealms2 = TRUE;
				}
				if (strcmp(section, "libdefaults") == 0) {
					wrotelibdefaults2 = TRUE;
				}
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
	if (!wrotelibdefaults2 &&
	    (non_empty(info->kerberosRealm) ||
	     info->kerberosRealmviaDNS ||
	     info->kerberosKDCviaDNS)) {
		if (!wrotelibdefaults) {
			strcat(obuf, "[libdefaults]\n");
		}
		strcat(obuf, " default_realm = ");
		strcat(obuf, info->kerberosRealm);
		strcat(obuf, "\n");
		strcat(obuf, " dns_lookup_realm = ");
		strcat(obuf, info->kerberosRealmviaDNS ?  "true" : "false");
		strcat(obuf, "\n");
		strcat(obuf, " dns_lookup_kdc = ");
		strcat(obuf, info->kerberosKDCviaDNS ?  "true" : "false");
		strcat(obuf, "\n\n");
	}

	/* If we haven't encountered a realms section yet... */
	if (!wroterealms2 && non_empty(info->kerberosRealm)) {
		if (!wroterealms) {
			strcat(obuf, "[realms]\n");
		}
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
static gboolean
authInfoWriteKerberos4(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL;
	char *p, *q;
	int fd, l;
	struct flock lock;
	struct stat st;

	if (is_empty(info->kerberosRealm)) {
		return FALSE;
	}

	fd = open(SYSCONFDIR "/krb.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		close(fd);
		return FALSE;
	}
	if (fstat(fd, &st) == -1) {
		close(fd);
		return FALSE;
	}

	ibuf = g_malloc0(st.st_size + 1);
	if (read(fd, ibuf, st.st_size) != st.st_size) {
		g_free(ibuf);
		close(fd);
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
	if (non_empty(p)) {
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
	if (non_empty(p)) {
		while (strchr(p, ',')) {
			strcat(obuf, info->kerberosRealm ?: "");
			strcat(obuf, "\t");
			strncat(obuf, p, strchr(p, ',') - p);
			strcat(obuf, " admin server\n");
			p = strchr(p, ',') + 1;
		}
	}
	if (non_empty(p)) {
		strcat(obuf, info->kerberosRealm ?: "");
		strcat(obuf, "\t");
		strcat(obuf, p);
		strcat(obuf, " admin server\n");
	}

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

/* Compare two strings, one a possible data line, the other a Samba-style key
 * name.  Returns -1 on non-match, offset into candidate if matched. */
static int
authInfoReadWinbindCheck(const char *candidate, const char *key)
{
	const char *words, *worde, *p, *q;
	int ret;

	/* Check for a match with the requested setting name. */
	p = candidate;
	words = key;
	ret = -1;

	while ((*words != '\0') && (*p != '\0')) {
		/* Find the end of this portion of the key name. */
		worde = words;
		while ((*worde != '\0') && !isspace(*worde)) {
			worde++;
		}
		/* Find the end of the word on the line. */
		q = p;
		while ((*q != '\0') && (*q != '=') && !isspace(*q)) {
			q++;
		}
		/* If the two words don't match, we're done here. */
		if (q - p != worde - words) {
			break;
		}
		if (strncasecmp(p, words, q - p) != 0) {
			break;
		}
		/* If worde points to a NUL (end of keyword) and the
		 * next token is an equal sign (end of keyword in
		 * file), then we have a match. */
		while ((*q != '\0') && isspace(*q)) {
			q++;
		}
		while ((*worde != '\0') && isspace(*worde)) {
			worde++;
		}
		if ((*q == '=') && (*worde == '\0')) {
			while ((*q == '=') || isspace(*q)) {
				q++;
			}
			if (*q != '\0') {
				ret = q - candidate;
				break;
			}
		}
		/* Check the next word. */
		words = worde;
		while ((*words != '\0') && isspace(*words)) {
			words++;
		}
		p = q;
		while ((*p != '\0') && isspace(*p)) {
			p++;
		}
	}
	return ret;
}

/* Read Samba setup from /etc/samba/smb.conf. */
static char *
authInfoReadWinbindGlobal(struct authInfoType *info, const char *key)
{
	FILE *fp = NULL;
	char buf[BUFSIZ], *p, *q;
	char *section = NULL, *result = NULL;
	int i;

	fp = fopen(SYSCONFDIR "/samba/smb.conf", "r");
	if (fp == NULL) {
		return NULL;
	}

	memset(buf, '\0', sizeof(buf));

	while ((fgets(buf, sizeof(buf) - 1, fp) != NULL) && (result == NULL)) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while ((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for (p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* Skip comments. */
		if (*p == '#') {
			continue;
		}
		if (*p == ';') {
			continue;
		}

		/* If it's a new section, note which one we're "in". */
		if (p[0] == '[') {
			p++;
			for (q = p; ((*q != ']') && (*q != '\0')); q++);

			if (section != NULL) {
				g_free(section);
				section = NULL;
			}
			if (q - p > 0)  {
				section = g_strndup(p, q - p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for global settings.  Anything else we can skip. */
		if (section == NULL) {
			continue;
		}
		if (strcasecmp(section, "global") != 0) {
			continue;
		}

		/* Check for a match with the requested setting name. */
		i = authInfoReadWinbindCheck(p, key);
		if (i >= 0) {
			result = g_strdup(p + i);
		}
	}

	if (section != NULL) {
		g_free(section);
	}

	fclose(fp);
	return result;
}

/* Read winbind settings from /etc/smb/samba.conf. */
gboolean
authInfoReadWinbind(struct authInfoType *info)
{
	char *tmp;

	tmp = authInfoReadWinbindGlobal(info, "workgroup");
	if (tmp != NULL) {
		if (info->smbWorkgroup != NULL) {
			g_free(info->smbWorkgroup);
		}
		info->smbWorkgroup = tmp;
	}

	tmp = authInfoReadWinbindGlobal(info, "password server");
	if (tmp != NULL) {
		if (info->smbServers != NULL) {
			g_free(info->smbServers);
		}
		info->smbServers = tmp;
	}

	tmp = authInfoReadWinbindGlobal(info, "realm");
	if (tmp != NULL) {
		if (info->smbRealm != NULL) {
			g_free(info->smbRealm);
		}
		info->smbRealm = tmp;
	}

	tmp = authInfoReadWinbindGlobal(info, "security");
	if (tmp != NULL) {
		if (info->smbSecurity != NULL) {
			g_free(info->smbSecurity);
		}
		info->smbSecurity = tmp;
	}
	if (is_empty(info->smbSecurity)) {
		info->smbSecurity = g_strdup("user");
	}

	tmp = authInfoReadWinbindGlobal(info, "idmap uid");
	if (tmp != NULL) {
		if (info->smbIdmapUid != NULL) {
			g_free(info->smbIdmapUid);
		}
		info->smbIdmapUid = tmp;
	}
	if (info->smbIdmapUid == NULL) {
		/* 2^24 to 2^25 - 1 should be safe */
		info->smbIdmapUid = g_strdup("16777216-33554431");
	}

	tmp = authInfoReadWinbindGlobal(info, "idmap gid");
	if (tmp != NULL) {
		if (info->smbIdmapGid != NULL) {
			g_free(info->smbIdmapGid);
		}
		info->smbIdmapGid = tmp;
	}
	if (info->smbIdmapGid == NULL) {
		/* 2^24 to 2^25 - 1 should be safe */
		info->smbIdmapGid = g_strdup("16777216-33554431");
	}

	tmp = authInfoReadWinbindGlobal(info, "winbind separator");
	if (tmp != NULL) {
		if (info->winbindSeparator != NULL) {
			g_free(info->winbindSeparator);
		}
		info->winbindSeparator = tmp;
	}
	tmp = authInfoReadWinbindGlobal(info, "template homedir");
	if (tmp != NULL) {
		if (info->winbindTemplateHomedir!= NULL) {
			g_free(info->winbindTemplateHomedir);
		}
		info->winbindTemplateHomedir = tmp;
	}
	tmp = authInfoReadWinbindGlobal(info, "template primary group");
	if (tmp != NULL) {
		if (info->winbindTemplatePrimaryGroup != NULL) {
			g_free(info->winbindTemplatePrimaryGroup);
		}
		info->winbindTemplatePrimaryGroup = tmp;
	}
	tmp = authInfoReadWinbindGlobal(info, "template shell");
	if (tmp != NULL) {
		if (info->winbindTemplateShell != NULL) {
			g_free(info->winbindTemplateShell);
		}
		info->winbindTemplateShell = tmp;
	}
	if (is_empty(info->winbindTemplateShell)) {
		info->winbindTemplateShell = g_strdup("/bin/false");
	}
	tmp = authInfoReadWinbindGlobal(info, "winbind use default domain");
	if (tmp != NULL) {
		if (strcasecmp(tmp, "yes") == 0) {
			info->winbindUseDefaultDomain = TRUE;
		} else {
			info->winbindUseDefaultDomain = FALSE;
		}
		g_free(tmp);
	}

	return TRUE;
}

/* Write winbind settings to /etc/smb/samba.conf. */
gboolean
authInfoWriteWinbind(struct authInfoType *info)
{
	int fd, len;
	struct flock lock;
	struct stat st;
	char *section, *p, *q, *ibuf, *obuf;
	gboolean wroteglobal, wroteglobal2, wroteworkgroup, wroteservers,
		 wroterealm, wrotesecurity, wroteidmapuid, wroteidmapgid,
		 wroteseparator, wrotetemplateh, wrotetemplatep,
		 wrotetemplates, wroteusedefaultdomain;

	fd = open(SYSCONFDIR "/samba/smb.conf", O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		close(fd);
		return FALSE;
	}
	if (fstat(fd, &st) == -1) {
		close(fd);
		return FALSE;
	}

	ibuf = g_malloc0(st.st_size + 1);
	if (read(fd, ibuf, st.st_size) != st.st_size) {
		g_free(ibuf);
		close(fd);
		return FALSE;
	}

	/* Determine the maximum length of the new file. */
	len = st.st_size + 1;
	len += strlen("\n[global]\n");

	len += strlen("   workgroup = \n");
	len += strlen(info->smbWorkgroup ?: " ");

	len += strlen("   password server = \n");
	len += strlen(info->smbServers ?: " ");

	len += strlen("   realm = \n");
	len += strlen(info->smbRealm ?: " ");

	len += strlen("   security = \n");
	len += strlen(info->smbSecurity ?: " ");

	len += strlen("   idmap uid = \n");
	len += strlen(info->smbIdmapUid ?: " ");

	len += strlen("   idmap gid = \n");
	len += strlen(info->smbIdmapGid ?: " ");

	len += strlen("   winbind separator = \n");
	len += strlen(info->winbindSeparator ?: " ");

	len += strlen("   template homedir = \n");
	len += strlen(info->winbindTemplateHomedir ?: " ");

	len += strlen("   template primary group = \n");
	len += strlen(info->winbindTemplatePrimaryGroup ?: " ");

	len += strlen("   template shell = \n");
	len += strlen(info->winbindTemplateShell ?: " ");

	len += strlen("   winbind use default domain = no \n");

	obuf = g_malloc0(len * 2);

	/* Iterate over all of the lines in the current contents. */
	p = ibuf;
	wroteglobal = FALSE;
	wroteglobal2 = FALSE;
	wroteworkgroup = FALSE;
	wroteservers = FALSE;
	wroterealm = FALSE;
	wrotesecurity = FALSE;
	wroteidmapuid = FALSE;
	wroteidmapgid = FALSE;
	wroteseparator = FALSE;
	wrotetemplateh = FALSE;
	wrotetemplatep = FALSE;
	wrotetemplates = FALSE;
	wroteusedefaultdomain = FALSE;
	section = NULL;
	while (*p != '\0') {
		/* Isolate a single line. */
		char *l = p;
		for (q = p; (*q != '\0') && (*q != '\n'); q++);
		if (*q != '\0') q++;

		/* Skip over any whitespace. */
		for (;isspace(*p) && (*p != '\0') && (*p != '\n'); p++);

		/* If it's a comment, just pass it through. */
		if ((*p == ';') || (*p == '#')) {
			strncat(obuf, l, q - l);
			p = q;
			continue;
		}

		/* If it's a section start, note the section name. */
		if (*p == '[') {
			char *c;
			gboolean leaving;
			p++;
			c = strchr(p, ']');
			if (c != NULL) {
				leaving = FALSE;
				if (section != NULL) {
					if (strcmp(section, "global") == 0) {
						leaving = TRUE;
						wroteglobal2 = TRUE;
					}
					g_free(section);
					section = NULL;
				}
				if (leaving) {
					if (!wroteworkgroup &&
					    non_empty(info->smbWorkgroup)) {
						strcat(obuf, "   workgroup = ");
						strcat(obuf, info->smbWorkgroup);
						strcat(obuf, "\n");
						wroteworkgroup = TRUE;
					}
					if (!wroteservers &&
					    non_empty(info->smbServers)) {
						char *tmp, *t;
						tmp = g_strdup(info->smbServers);
						while ((t = strchr(tmp, ',')) != NULL) {
							*t = ' ';
						}
						strcat(obuf, "   password server = ");
						strcat(obuf, tmp);
						strcat(obuf, "\n");
						g_free(tmp);
						wroteservers = TRUE;
					}
					if (!wroterealm &&
					    non_empty(info->smbRealm)) {
						strcat(obuf, "   realm = ");
						strcat(obuf, info->smbRealm);
						strcat(obuf, "\n");
						wroterealm = TRUE;
					}
					if (!wrotesecurity &&
					    non_empty(info->smbSecurity)) {
						strcat(obuf, "   security = ");
						strcat(obuf, info->smbSecurity);
						strcat(obuf, "\n");
						wrotesecurity = TRUE;
					}
					if (!wroteidmapuid &&
					    non_empty(info->smbIdmapUid)) {
						strcat(obuf, "   idmap uid = ");
						strcat(obuf, info->smbIdmapUid);
						strcat(obuf, "\n");
						wroteidmapuid = TRUE;
					}
					if (!wroteidmapgid &&
					    non_empty(info->smbIdmapGid)) {
						strcat(obuf, "   idmap gid = ");
						strcat(obuf, info->smbIdmapGid);
						strcat(obuf, "\n");
						wroteidmapgid = TRUE;
					}
					if (!wroteseparator &&
					    non_empty(info->winbindSeparator)) {
						strcat(obuf, "   winbind separator = ");
						strcat(obuf, info->winbindSeparator);
						strcat(obuf, "\n");
						wroteseparator = TRUE;
					}
					if (!wrotetemplateh &&
					    non_empty(info->winbindTemplateHomedir)) {
						strcat(obuf, "   template homedir = ");
						strcat(obuf, info->winbindTemplateHomedir);
						strcat(obuf, "\n");
						wrotetemplateh = TRUE;
					}
					if (!wrotetemplatep &&
					    non_empty(info->winbindTemplatePrimaryGroup)) {
						strcat(obuf, "   template primary group = ");
						strcat(obuf, info->winbindTemplatePrimaryGroup);
						strcat(obuf, "\n");
						wrotetemplatep = TRUE;
					}
					if (!wrotetemplates &&
					    non_empty(info->winbindTemplateShell)) {
						strcat(obuf, "   template shell = ");
						strcat(obuf, info->winbindTemplateShell);
						strcat(obuf, "\n");
						wrotetemplates = TRUE;
					}
					if (!wroteusedefaultdomain) {
						strcat(obuf, "   winbind use default domain = ");
						strcat(obuf, info->winbindUseDefaultDomain ? "yes" : "no");
						strcat(obuf, "\n");
						wroteusedefaultdomain = TRUE;
					}
				}
				section = g_strndup(p, c - p);
				if (strcmp(section, "global") == 0) {
					wroteglobal = TRUE;
				}
			}
			strncat(obuf, l, q - l);
			p = q;
			continue;
		}

		/* If it's the wrong section, pass it through. */
		if ((section == NULL) || (strcmp(section, "global") != 0)) {
			strncat(obuf, l, q - l);
			p = q;
			continue;
		}

		/* Check if this is a setting we care about. */
		if (authInfoReadWinbindCheck(p, "workgroup") >= 0) {
			if (non_empty(info->smbWorkgroup)) {
				strcat(obuf, "   workgroup = ");
				strcat(obuf, info->smbWorkgroup);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wroteworkgroup = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "password server") >= 0) {
			if (non_empty(info->smbServers)) {
				char *tmp, *t;
				tmp = g_strdup(info->smbServers);
				while ((t = strchr(tmp, ',')) != NULL) {
					*t = ' ';
				}
				strcat(obuf, "   password server = ");
				strcat(obuf, tmp);
				strcat(obuf, "\n");
				g_free(tmp);
			} else {
				strncat(obuf, l, q - l);
			}
			wroteservers = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "realm") >= 0) {
			if (non_empty(info->smbRealm)) {
				strcat(obuf, "   realm = ");
				strcat(obuf, info->smbRealm);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wroterealm = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "security") >= 0) {
			if (non_empty(info->smbSecurity)) {
				strcat(obuf, "   security = ");
				strcat(obuf, info->smbSecurity);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wrotesecurity = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "idmap uid") >= 0) {
			if (non_empty(info->smbIdmapUid)) {
				strcat(obuf, "   idmap uid = ");
				strcat(obuf, info->smbIdmapUid);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wroteidmapuid = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "idmap gid") >= 0) {
			if (non_empty(info->smbIdmapGid)) {
				strcat(obuf, "   idmap gid = ");
				strcat(obuf, info->smbIdmapGid);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wroteidmapgid = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "winbind separator") >= 0) {
			if (non_empty(info->winbindSeparator)) {
				strcat(obuf, "   winbind separator = ");
				strcat(obuf, info->winbindSeparator);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wroteseparator = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "template homedir") >= 0) {
			if (non_empty(info->winbindTemplateHomedir)) {
				strcat(obuf, "   template homedir = ");
				strcat(obuf, info->winbindTemplateHomedir);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wrotetemplateh = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "template primary group") >= 0) {
			if (non_empty(info->winbindTemplatePrimaryGroup)) {
				strcat(obuf, "   template primary group = ");
				strcat(obuf, info->winbindTemplatePrimaryGroup);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wrotetemplatep = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "template shell") >= 0) {
			if (non_empty(info->winbindTemplateShell)) {
				strcat(obuf, "   template shell = ");
				strcat(obuf, info->winbindTemplateShell);
				strcat(obuf, "\n");
			} else {
				strncat(obuf, l, q - l);
			}
			wrotetemplates = TRUE;
			p = q;
			continue;
		}
		if (authInfoReadWinbindCheck(p, "winbind use default domain") >= 0) {
			strcat(obuf, "   winbind use default domain = ");
			strcat(obuf, info->winbindUseDefaultDomain ? "yes" : "no");
			strcat(obuf, "\n");
			wroteusedefaultdomain = TRUE;
			p = q;
			continue;
		}

		/* It's not a setting we care about, so pass it through. */
		strncat(obuf, l, q - l);
		p = q;
	}

	/* If we didn't finish writing a [global] section, add one. */
	if (!wroteglobal) {
		strcat(obuf, "\n[global]\n");
	}
	if (!wroteglobal2) {
		if (!wroteworkgroup && non_empty(info->smbWorkgroup)) {
			strcat(obuf, "   workgroup = ");
			strcat(obuf, info->smbWorkgroup);
			strcat(obuf, "\n");
		}
		if (!wroteservers && non_empty(info->smbServers)) {
			char *tmp, *t;
			tmp = g_strdup(info->smbServers);
			while ((t = strchr(tmp, ',')) != NULL) {
				*t = ' ';
			}
			strcat(obuf, "   password server = ");
			strcat(obuf, tmp);
			strcat(obuf, "\n");
			g_free(tmp);
		}
		if (!wroterealm && non_empty(info->smbRealm)) {
			strcat(obuf, "   realm = ");
			strcat(obuf, info->smbRealm);
			strcat(obuf, "\n");
		}
		if (!wrotesecurity && non_empty(info->smbSecurity)) {
			strcat(obuf, "   security = ");
			strcat(obuf, info->smbSecurity);
			strcat(obuf, "\n");
		}
		if (!wroteidmapuid && non_empty(info->smbIdmapUid)) {
			strcat(obuf, "   idmap uid = ");
			strcat(obuf, info->smbIdmapUid);
			strcat(obuf, "\n");
		}
		if (!wroteidmapgid && non_empty(info->smbIdmapGid)) {
			strcat(obuf, "   idmap gid = ");
			strcat(obuf, info->smbIdmapGid);
			strcat(obuf, "\n");
		}
		if (!wroteseparator && non_empty(info->winbindSeparator)) {
			strcat(obuf, "   winbind separator = ");
			strcat(obuf, info->winbindSeparator);
			strcat(obuf, "\n");
		}
		if (!wrotetemplateh && non_empty(info->winbindTemplateHomedir)) {
			strcat(obuf, "   template homedir = ");
			strcat(obuf, info->winbindTemplateHomedir);
			strcat(obuf, "\n");
		}
		if (!wrotetemplatep && non_empty(info->winbindTemplatePrimaryGroup)) {
			strcat(obuf, "   template primary group = ");
			strcat(obuf, info->winbindTemplatePrimaryGroup);
			strcat(obuf, "\n");
		}
		if (!wrotetemplates && non_empty(info->winbindTemplateShell)) {
			strcat(obuf, "   template shell = ");
			strcat(obuf, info->winbindTemplateShell);
			strcat(obuf, "\n");
		}
		if (!wroteusedefaultdomain && non_empty(info->winbindTemplateShell)) {
			strcat(obuf, "   winbind use default domain = ");
			strcat(obuf, info->winbindUseDefaultDomain ? "yes" : "no");
			strcat(obuf, "\n");
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

/* Write NSS setup to /etc/nsswitch.conf. */
gboolean
authInfoWriteNSS(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	char users[BUFSIZ] = "", normal[BUFSIZ] = "", hosts[BUFSIZ] = "";
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
		close(fd);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
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
	l += strlen(" compat") * 8;
	l += strlen(" db") * 8;
	l += strlen(" files") * 8;
	l += strlen(" directories") * 8;
	l += strlen(" wins") * 8;
	l += strlen(" winbind") * 8;
	l += strlen(" odbcbind") * 8;
	l += strlen(" nisplus") * 8;
	l += strlen(" nis") * 8;
	l += strlen(" hesiodbind") * 8;
	l += strlen(" hesiod") * 8;
	l += strlen(" ldapbind") * 8;
	l += strlen(" ldap") * 8;
	l += strlen(" dns");
	l += strlen(" dbibind") * 8;
	l += strlen(" dbbind") * 8;
	obuf = g_malloc0(st.st_size + 1 + l);

	/* Determine what we want in that file for most of the databases.  If
	 * we're using DB, we're doing it for speed, so put it in first.  Then
	 * comes files.  Then everything else in reverse alphabetic order. */
	if (info->enableDB) strcat(normal, " db");
	strcat(normal, " files");
	if (info->enableDirectories) strcat(normal, " directories");
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

	/* Generate the list for users and groups.  The same as most other
	 * services, just use "compat" instead of "files" if "compat" is
	 * enabled. */
	strcpy(users, normal);
	if (info->enableCompat) {
		char *dest, *src;
		dest = strstr(users, "files");
		src = strstr(normal, "files");
		strcpy(dest, "compat ");
		strcpy(dest + 7, src + 6);
	}

	/* Hostnames we treat specially. */
	strcat(hosts, " files");
	if (info->enableWINS) strcat(hosts, " wins");
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
				strcat(obuf, users);
				strcat(obuf, "\n");
				wrotepasswd = TRUE;
			}
		} else

		/* If it's a 'shadow' line, insert ours instead. */
		if (strncmp("shadow:", p, 7) == 0) {
			if (!wroteshadow) {
				strcat(obuf, "shadow:    ");
				strcat(obuf, users);
				strcat(obuf, "\n");
				wroteshadow = TRUE;
			}
		} else

		/* If it's a 'group' line, insert ours instead. */
		if (strncmp("group:", p, 6) == 0) {
			if (!wrotegroup) {
				strcat(obuf, "group:     ");
				strcat(obuf, users);
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
		} else {
			/* Otherwise, just copy the current line out. */
			strncat(obuf, p, q - p);
		}

		/* Advance to the next line. */
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

static const char *argv_passwdqc_password[] = {
	"enforce=users",
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

static const char *argv_succeed_if_account[] = {
	"uid < 100",
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
	{TRUE,  account,	LOGIC_SUFFICIENT,
	 "succeed_if",		argv_succeed_if_account},
	{TRUE,  account,	LOGIC_REQUIRED,
	 "unix",		NULL},
	{FALSE, account,	LOGIC_IGNORE_UNKNOWN,
	 "ldap",		NULL},
	{FALSE, account,	LOGIC_IGNORE_UNKNOWN,
	 "krb5",		NULL},
	{FALSE, account,	LOGIC_IGNORE_UNKNOWN,
	 "krb5afs",		NULL},
	{FALSE, account,	LOGIC_IGNORE_UNKNOWN,
	 "winbind",		NULL},

#ifdef LOCAL_POLICIES
	{FALSE, password,	LOGIC_REQUIRED,
	 "stack",		argv_local_all},
#endif
	{FALSE,  password,	LOGIC_REQUISITE,
	 "cracklib",		argv_cracklib_password},
	{FALSE,  password,	LOGIC_REQUISITE,
	 "passwdqc",		argv_passwdqc_password},
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
	switch (standard_pam_modules[i].stack) {
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
			char buf[BUFSIZ];
			char *args;
			memset(buf, '\0', sizeof(buf));
			snprintf(buf, sizeof(buf) - 1,
				 "%-12s%-13s %s/pam_%s.so", stack, logic,
				 AUTH_MODULE_DIR, standard_pam_modules[i].name);
			args = NULL;
			if (strcmp(standard_pam_modules[i].name,
				   "cracklib") == 0) {
				args = info->cracklibArgs;
			}
			if (strcmp(standard_pam_modules[i].name,
				   "passwdqc") == 0) {
				args = info->passwdqcArgs;
			}
			if ((args == NULL) &&
			    (standard_pam_modules[i].argv != NULL)) {
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
			if (args != NULL) {
				strcat(obuf, " ");
				strcat(obuf, args);
			}
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

	obuf = g_malloc0(BUFSIZ *
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
		   (authInfo->enableCracklib &&
		    (strcmp("cracklib", standard_pam_modules[i].name) == 0)) ||
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
		   (authInfo->enablePasswdQC &&
		    (strcmp("passwdqc", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableSMB &&
		    (strcmp("smb_auth", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableWinbind &&
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
		svSetValue(sv, "USECRACKLIB",
			   authInfo->enableCracklib ? "yes" : "no");
		svSetValue(sv, "USEDB",
			   authInfo->enableDB ? "yes" : "no");
#ifdef EXPERIMENTAL
		/* We don't save these settings yet, because we have no
		 * way to present the user with the option. */
		svSetValue(sv, "USEDBBIND",
			   authInfo->enableDBbind ? "yes" : "no");
		svSetValue(sv, "USEDBIBIND",
			   authInfo->enableDBIbind ? "yes" : "no");
		svSetValue(sv, "USEDIRECTORIES",
			   authInfo->enableDirectories ? "yes" : "no");
#endif
		svSetValue(sv, "USEHESIOD",
			   authInfo->enableHesiod ? "yes" : "no");
#ifdef EXPERIMENTAL
		svSetValue(sv, "USEHESIODBIND",
			   authInfo->enableHesiodbind ? "yes" : "no");
#endif
		svSetValue(sv, "USELDAP",
			   authInfo->enableLDAP ? "yes" : "no");
#ifdef EXPERIMENTAL
		svSetValue(sv, "USELDAPBIND",
			   authInfo->enableLDAPbind ? "yes" : "no");
#endif
		svSetValue(sv, "USENIS",
			   authInfo->enableNIS ? "yes" : "no");
#ifdef EXPERIMENTAL
		svSetValue(sv, "USENISPLUS",
			   authInfo->enableNIS3 ? "yes" : "no");
		svSetValue(sv, "USEODBCBIND",
			   authInfo->enableOdbcbind ? "yes" : "no");
#endif
		svSetValue(sv, "USEPASSWDQC",
			   authInfo->enablePasswdQC ? "yes" : "no");
		svSetValue(sv, "USEWINBIND",
			   authInfo->enableWinbind ? "yes" : "no");

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

	authInfoUpdate(authInfo);

	ret = authInfoWriteLibuser(authInfo);
	ret = authInfoWriteCache(authInfo);
	if (authInfo->enableHesiod)
		ret = ret && authInfoWriteHesiod(authInfo);
	if (authInfo->enableLDAP)
		ret = ret && authInfoWriteLDAP(authInfo);
	if (authInfo->enableKerberos ||
	    (authInfo->enableWinbind &&
	     non_empty(authInfo->smbSecurity) &&
	     (strcmp(authInfo->smbSecurity, "ads") == 0)))
		ret = ret && authInfoWriteKerberos(authInfo);
	if (authInfo->enableNIS)
		ret = ret && authInfoWriteNIS(authInfo);
	if (authInfo->enableSMB)
		ret = ret && authInfoWriteSMB(authInfo);
	if (authInfo->enableWinbind)
		ret = ret && authInfoWriteWinbind(authInfo);
	ret = ret && authInfoWriteNSS(authInfo);
	ret = ret && authInfoWritePAM(authInfo);
	ret = ret && authInfoWriteNetwork(authInfo);
	return ret;
}

static void
terminate_hostname(char *hostname)
{
	if (hostname[strlen(hostname) - 1] == '.'){
		hostname[strlen(hostname) - 1] = '\0';
	}
}

static char *
domain2dn(const char *domain)
{
	char buf[BUFSIZ], dbuf[BUFSIZ];
	int i;
	strcpy(buf, "DC=");
	strncpy(dbuf, domain, sizeof(dbuf) - 1);
	dbuf[sizeof(dbuf) - 1] = '\0';
	terminate_hostname(dbuf);
	for (i = 0; (dbuf[i] != '\0') && (strlen(buf) < sizeof(buf) - 5); i++){
		if (dbuf[i] == '.') {
			strcat(buf, ",DC=");
		} else {
			strncat(buf, dbuf + i, 1);
		}
	}
	return g_strdup(buf);
}

#define DEFAULT_DNS_QUERY_SIZE 1024

struct authInfoType *
authInfoProbe()
{
	struct authInfoType *ret = NULL;
	char hostname[BUFSIZ], qname[BUFSIZ];
	struct dns_client *client = NULL;
	struct dns_rr *results = NULL, *result = NULL;
	struct {
		int hclass;
		char *hdomain;
	} hesiod[] = {
		{DNS_C_IN, "hs"},
		{DNS_C_IN, "ns"},
		{DNS_C_HS, "hs"},
		{DNS_C_HS, "ns"},
	};
	int i;
	char *p;

	ret = g_malloc0(sizeof(struct authInfoType));
	client = dns_client_new();

	/* get the local host name */
	memset(hostname, '\0', sizeof(hostname));
	gethostname(hostname, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = '\0';

	if (strlen(hostname) == 0) {
		return ret;
	}

	/* terminate the host name */
	p = strrchr(hostname, '.');
	if (p != NULL) {
		if (p - hostname != (strlen(hostname) - 1)) {
			strncat(hostname, ".",
				sizeof(hostname) - strlen(hostname) - 1);
		}
	} else {
		strncat(hostname, ".", sizeof(hostname) - strlen(hostname) - 1);
	}

	/* first, check for an LDAP server for the local domain */
	results = NULL;
	if ((p = strchr(hostname, '.')) != NULL) {
		snprintf(qname, sizeof(qname), "_ldap._tcp%s", p);
		results = dns_client_query(client, qname, DNS_C_IN, DNS_T_SRV);
	}

	result = results;
	while ((result != NULL) && (result->dns_name != NULL)) {
		if ((result->dns_type == DNS_T_SRV) &&
		    (result->dns_rdata.srv.server != NULL)) {
			ret->ldapServer = g_strdup(result->dns_rdata.srv.server);
			terminate_hostname(ret->ldapServer);
			if (p != NULL) {
				ret->ldapBaseDN = domain2dn(++p);
				p = NULL;
			}
		}
		result++;
	}

	/* now, check for a Kerberos realm the local host or domain is in */
	results = NULL;
	snprintf(qname, sizeof(qname), "_kerberos.%s", hostname);
	results = dns_client_query(client, qname, DNS_C_IN, DNS_T_TXT);
	if ((results == NULL) && ((p = strchr(hostname, '.')) != NULL)) {
		snprintf(qname, sizeof(qname), "_kerberos%s", p);
		results = dns_client_query(client, qname, DNS_C_IN, DNS_T_TXT);
	}
	result = results;
	while ((result != NULL) && (result->dns_name != NULL)) {
		if ((result->dns_type == DNS_T_TXT) &&
		    (result->dns_rdata.txt.data != NULL)) {
			ret->kerberosRealm = g_strdup(result->dns_rdata.txt.data);
			break;
		}
		result++;
	}

	/* now fetch server information for the realm */
	results = NULL;
	if (ret->kerberosRealm) {
		snprintf(qname, sizeof(qname), "_kerberos._udp.%s",
			 ret->kerberosRealm);
		results = dns_client_query(client, qname, DNS_C_IN, DNS_T_SRV);
	}

	result = results;
	while ((result != NULL) && (result->dns_name != NULL)) {
		if ((result->dns_type == DNS_T_SRV) &&
		    (result->dns_rdata.srv.server != NULL)) {
			snprintf(qname, sizeof(qname), "%s",
				 result->dns_rdata.srv.server);
			if (result->dns_rdata.srv.port != 0) {
				snprintf(qname + strlen(qname),
					 sizeof(qname) - strlen(qname),
					 ":%d",
					 result->dns_rdata.srv.port);
			}
			if (ret->kerberosKDC != NULL) {
				p = g_strconcat(ret->kerberosKDC,
				                ",",
						qname,
						NULL);
				g_free(ret->kerberosKDC);
				ret->kerberosKDC = p;
			} else {
				ret->kerberosKDC = g_strdup(qname);
			}
		}
		result++;
	}

	/* now fetch admin server information for the realm */
	results = NULL;
	if (ret->kerberosRealm) {
		snprintf(qname, sizeof(qname), "_kerberos-adm._udp.%s",
			 ret->kerberosRealm);
		results = dns_client_query(client, qname, DNS_C_IN, DNS_T_SRV);
	}

	/* use all values */
	memset(qname, '\0', sizeof(qname));
	result = results;
	while ((result != NULL) && (result->dns_name != NULL)) {
		if ((result->dns_type == DNS_T_SRV) &&
		    (result->dns_rdata.srv.server != NULL)) {
			snprintf(qname, sizeof(qname), "%s",
				 result->dns_rdata.srv.server);
			if (result->dns_rdata.srv.port != 0) {
				snprintf(qname + strlen(qname),
					 sizeof(qname) - strlen(qname),
					 ":%d",
					 result->dns_rdata.srv.port);
			}
			if (ret->kerberosAdminServer != NULL) {
				p = g_strconcat(ret->kerberosAdminServer,
				                ",",
						qname,
						NULL);
				g_free(ret->kerberosAdminServer);
				ret->kerberosAdminServer = p;
			} else {
				ret->kerberosAdminServer = g_strdup(qname);
			}
		}
		result++;
	}

	/* now check for SOA records for hesiod-style domains under .hs.DOMAIN
	 * and .ns.DOMAIN */
	if ((p = strchr(hostname, '.')) != NULL) {
		for (i = 0; i < G_N_ELEMENTS(hesiod); i++) {
			snprintf(qname, sizeof(qname), "%s%s",
				 hesiod[i].hdomain, p);
			results = dns_client_query(client, qname,
						   hesiod[i].hclass, DNS_T_SOA);
			result = results;
			while ((result != NULL) && (result->dns_name != NULL)) {
				if ((result->dns_type == DNS_T_SOA) &&
				    (strcmp(result->dns_name, qname) == 0)) {
					ret->hesiodLHS = g_strdup_printf(".%s", hesiod[i].hdomain);
					ret->hesiodRHS = g_strdup(p);
					terminate_hostname(ret->hesiodRHS);
					break;
				}
				result++;
			}
		}
	}

	dns_client_free(client);

	return ret;
}

static gboolean
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
		domainStr = g_strdup_printf("/bin/domainname %s", nisDomain);
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
					system("/sbin/service ypbind restart");
				} else {
					system("/sbin/service ypbind start");
				}
			}
		}
	} else {
		system("/bin/domainname \"(none)\"");
		if (stat(PATH_YPBIND, &st) == 0) {
			if (!nostart) {
				if (stat(PATH_YPBIND_PID, &st) == 0) {
					system("/sbin/service ypbind stop");
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

static gboolean
toggleWinbindService(gboolean enableWinbind, gboolean nostart)
{
	struct stat st;

	if (enableWinbind) {
		if (stat(PATH_WINBIND, &st) == 0) {
			system("/sbin/chkconfig --add winbind");
			system("/sbin/chkconfig --level 345 winbind on");
			if (!nostart) {
				system("/sbin/service winbind restart");
			}
		}
	} else {
		if (stat(PATH_WINBIND, &st) == 0) {
			if (!nostart) {
				if (stat(PATH_WINBIND_PID, &st) == 0) {
					system("/sbin/service winbind stop");
				}
			}
			system("/sbin/chkconfig --del winbind");
		}
	}

	return TRUE;
}

static gboolean
toggleSplatbindService(gboolean enable, const char *path, const char *pidfile,
		       const char *name, gboolean nostart)
{
	struct stat st;
	char buf[LINE_MAX];

	if (enable) {
		if (stat(path, &st) == 0) {
			snprintf(buf, sizeof(buf),
				 "/sbin/chkconfig --add %s", name);
			system(buf);
			snprintf(buf, sizeof(buf),
				 "/sbin/chkconfig --level 345 %s on", name);
			system(buf);
			if (!nostart) {
				snprintf(buf, sizeof(buf),
					 "/sbin/service %s restart", name);
				system(buf);
			}
		}
	} else {
		if (stat(path, &st) == 0) {
			if (!nostart) {
				if (stat(pidfile, &st) == 0) {
					snprintf(buf, sizeof(buf),
						 "/sbin/service %s stop", name);
					system(buf);
				}
			}
			snprintf(buf, sizeof(buf),
				 "/sbin/chkconfig --del %s", name);
			system(buf);
		}
	}

	return TRUE;
}

void
authInfoPrint(struct authInfoType *authInfo)
{
    printf("caching is %s\n", authInfo->enableCache ? "enabled" : "disabled");
    printf("nss_files is always enabled\n");
    printf("nss_compat is %s\n",
	   authInfo->enableCompat ? "enabled" : "disabled");
    printf("nss_db is %s\n",
	   authInfo->enableDB ? "enabled" : "disabled");
#ifdef EXPERIMENTAL
    printf("nss_directories is %s\n",
	   authInfo->enableDirectories ? "enabled" : "disabled");
#endif
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
    printf("nss_nisplus is %s\n",
	   authInfo->enableNIS3 ? "enabled" : "disabled");
    printf("nss_winbind is %s\n",
	   authInfo->enableWinbind ? "enabled" : "disabled");
    printf("nss_wins is %s\n",
	   authInfo->enableWINS ? "enabled" : "disabled");
#ifdef EXPERIMENTAL
    printf("nss_dbbind is %s\n",
	   authInfo->enableDBbind ? "enabled" : "disabled");
    printf("nss_dbibind is %s\n",
	   authInfo->enableDBIbind ? "enabled" : "disabled");
    printf("nss_hesiodbind is %s\n",
	   authInfo->enableHesiodbind ? "enabled" : "disabled");
    printf("nss_ldapbind is %s\n",
	   authInfo->enableLDAPbind ? "enabled" : "disabled");
    printf("nss_odbcbind is %s\n",
	   authInfo->enableOdbcbind ? "enabled" : "disabled");
#endif
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
    printf(" krb5 realm via dns is %s\n",
	   authInfo->kerberosRealmviaDNS ? "enabled" : "disabled");
    printf(" krb5 kdc = \"%s\"\n",
	   authInfo->kerberosKDC ?: "");
    printf(" krb5 kdc via dns is %s\n",
	   authInfo->kerberosKDCviaDNS ? "enabled" : "disabled");
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
    printf(" SMB realm = \"%s\"\n",
	   authInfo->smbRealm ?: "");
    printf(" SMB servers = \"%s\"\n",
	   authInfo->smbServers ?: "");
    printf("pam_winbind is %s\n",
	   authInfo->enableWinbind ? "enabled" : "disabled");
    printf(" SMB security = \"%s\"\n",
	   authInfo->smbSecurity ?: "");
    printf(" SMB idmap uid = \"%s\"\n",
	   authInfo->smbIdmapUid ?: "");
    printf(" SMB idmap gid = \"%s\"\n",
	   authInfo->smbIdmapGid ?: "");
    printf(" Winbind template shell = \"%s\"\n",
	   authInfo->winbindTemplateShell ?: "");
    printf("pam_cracklib is %s (%s)\n",
	   authInfo->enableCracklib ? "enabled" : "disabled",
	   authInfo->cracklibArgs ? authInfo->cracklibArgs : "");
    printf("pam_passwdqc is %s (%s)\n",
	   authInfo->enablePasswdQC ? "enabled" : "disabled",
	   authInfo->passwdqcArgs ? authInfo->passwdqcArgs : "");
}

static void
feedFork(const char *command, gboolean echo,
         const char *query, const char *response)
{
    pid_t pid, child;
    int master, status, i;
    struct timeval tv;
    GString *str;
    fd_set fds;
    char c;
    gboolean eof;

    master = -1;
    pid = forkpty(&master, NULL, NULL, NULL);
    switch (pid) {
    case -1:
        /* uh, hide */
        break;
    case 0:
        /* child */
	system(command);
	_exit(0);
	break;
    default:
        str = g_string_new("");
	i = fcntl(master, F_GETFL);
	if (i != -1) {
	    fcntl(master, F_SETFL, i & ~O_NONBLOCK);
	}
	eof = FALSE;
	while (!eof) {
	    FD_ZERO(&fds);
	    FD_SET(master, &fds);
	    tv.tv_sec = 600;
	    tv.tv_usec = 0;
	    if ((i = select(master + 1, &fds, NULL, &fds, &tv)) != 1) {
	        if (i == -1) {
	            perror("select");
		}
	        kill(pid, SIGINT);
	        break;
	    }
	    child = waitpid(pid, &status, WNOHANG);
            switch (child) {
	    case -1:
                perror("waitpid");
                break;
	    case 0:
                break;
	    default:
	        g_assert(child == pid);
	        close(master);
		eof = TRUE;
                continue;
                break;
            }
	    switch (read(master, &c, sizeof(c))) {
	    case -1:
	        switch (errno) {
		case EINTR:
		case EAGAIN:
		    break;
                case EIO:
	            close(master);
		    eof = TRUE;
		    break;
		default:
		    perror("read");
	            close(master);
		    eof = TRUE;
		    break;
		}
		break;
	    case 0:
	        close(master);
		eof = TRUE;
		break;
	    case 1:
	        g_string_append_c(str, c);
	        if (echo) {
		    fprintf(stderr, "%c", c);
	        }
	        if (strstr(str->str, query) != NULL) {
	            write(master, response, strlen(response));
	            write(master, "\r\n", 2);
		    fsync(master);
		    g_string_truncate(str, 0);
		    fprintf(stderr, "<...>\n");
	        }
	        break;
            default:
	        break;
	    }
	}
        g_string_free(str, TRUE);
    }
}

void
authInfoJoin(struct authInfoType *authInfo, gboolean echo)
{
    if (authInfo->enableWinbind && (authInfo->joinUser != NULL)) {
        const char *domain, *server, *protocol;
        char *cmd, *p;
        protocol = "ads";
        server = NULL;
        domain = NULL;
        if (non_empty(authInfo->smbWorkgroup)) {
            domain = authInfo->smbWorkgroup;
        }
        if (non_empty(authInfo->smbSecurity)) {
            protocol = authInfo->smbSecurity;
        }
        if (non_empty(authInfo->smbServers)) {
            server = g_strdup(authInfo->smbServers);
            p = strpbrk(server, ", \t");
            if (p != NULL) {
                *p = '\0';
            }
        }
        if (is_empty(protocol)) {
	    return;
	}
	if ((strcmp(protocol, "ads") != 0) &&
	    (strcmp(protocol, "domain") != 0)) {
	    /* Not needed. */
	    return;
	}
        cmd = g_strdup_printf("/usr/bin/net %s %s %s %s %s %s -U %s",
                              protocol,
                              "join",
                              domain ? "-w" : "", domain ? domain : "",
                              server ? "-S" : "", server ? server : "",
                              authInfo->joinUser);
        p = cmd;
	while ((p = strstr(p, "  ")) != NULL) {
	    memmove(p, p + 1, strlen(p));
	}
        if (echo) {
	    fprintf(stderr, "[%s]\n", cmd);
        }
        if (authInfo->joinPassword != NULL) {
            feedFork(cmd, echo, "sword:", authInfo->joinPassword);
        } else {
            system(cmd);
        }
        g_free(cmd);
    }
}

void
authInfoPost(struct authInfoType *authInfo, int nostart)
{
    toggleShadow(authInfo);
    toggleNisService(authInfo->enableNIS, authInfo->nisDomain, nostart);
    toggleWinbindService(authInfo->enableWinbind, nostart);
    toggleSplatbindService(authInfo->enableDBbind,
			   PATH_DBBIND, PATH_DBBIND_PID,
			   "dbbind", nostart);
    toggleSplatbindService(authInfo->enableDBIbind,
			   PATH_DBIBIND, PATH_DBIBIND_PID,
			   "dbibind", nostart);
    toggleSplatbindService(authInfo->enableHesiodbind,
			   PATH_HESIODBIND, PATH_HESIODBIND_PID,
			   "hesiodbind", nostart);
    toggleSplatbindService(authInfo->enableLDAPbind,
			   PATH_LDAPBIND, PATH_LDAPBIND_PID,
			   "ldapbind", nostart);
    toggleSplatbindService(authInfo->enableOdbcbind,
			   PATH_ODBCBIND, PATH_ODBCBIND_PID,
			   "odbcbind", nostart);
    toggleCachingService(authInfo->enableCache, nostart);
}
