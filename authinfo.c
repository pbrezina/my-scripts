/*
 * Authconfig - authentication configuration program
 * Copyright (c) 1999, 2000 Red Hat, Inc.
 *
 * This program is licensed under the terms of the GPL.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <libgen.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shvar.h"
#include "authinfo.h"

/* Read hesiod setup.  Luckily, /etc/hesiod.conf is simple enough that shvar
 * can read it just fine. */
gboolean authInfoReadHesiod(struct authInfoType *info)
{
	shvarFile *sv = NULL;
	char *tmp = NULL;

	sv = svNewFile(SYSCONFDIR "/hesiod.conf");
	if(sv == NULL) {
		return FALSE;
	}

	tmp = svGetValue(sv, "lhs");
	if(tmp != NULL) {
		info->hesiodLHS = g_strdup(tmp);
		free(tmp);
		tmp = info->hesiodLHS + strlen(info->hesiodLHS);
		while((tmp > info->hesiodLHS) && isspace(tmp[-1])) {
			tmp[-1] = '\0';
			tmp--;
		}
	}

	tmp = svGetValue(sv, "rhs");
	if(tmp != NULL) {
		info->hesiodRHS = g_strdup(tmp);
		free(tmp);
		tmp = info->hesiodRHS + strlen(info->hesiodRHS);
		while((tmp > info->hesiodRHS) && isspace(tmp[-1])) {
			tmp[-1] = '\0';
			tmp--;
		}
	}

	svWriteFile(sv, 0644);
	svCloseFile(sv);
	sv = NULL;
	return TRUE;
}

/* Read NIS setup from /etc/yp.conf. */
gboolean authInfoReadNIS(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p, *q;

	/* Read NIS setup. */
	fp = fopen(SYSCONFDIR "/yp.conf", "r");
	if(fp == NULL) {
		return FALSE;
	}

	memset(buf, '\0', sizeof(buf));
	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for(p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* Is it a "ypserver" statement? */
		if(strncmp("ypserver", p, 8) == 0) {
			/* Skip intervening whitespace. */
			for(p += 8; (isspace(*p) && (*p != '\0')); p++);

			/* Save the server's name. */
			if(*p != '\0') {
				info->nisServer = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* It had better be a "domain" statement. */
		if(strncmp("domain", p, 6) == 0) {
			/* Skip intervening whitespace. */
			for(p += 6; (isspace(*p) && (*p != '\0')); p++);

			/* Save the domain's name.  To do that, find its end. */
			for(q = p; (!isspace(*q) && (*q != '\0')); q++);
			if(*p != '\0') {
				info->nisDomain = g_strndup(p, q - p);
			}

			/* Skip over some more whitespace. */
			for(p = q; (isspace(*p) && (*p != '\0')); p++);

			/* Is it "server"?  If not, assume "broadcast". */
			if(strncmp(p, "server", 6) == 0) {
				for(p += 6; (isspace(*p) && (*p != '\0')); p++);
				if(*p != '\0') {
					info->nisServer = g_strdup(p);
				}
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		memset(buf, '\0', sizeof(buf));
	}

	fclose(fp);
	return TRUE;
}

/* Read LDAP setup from /etc/ldap.conf. */
gboolean authInfoReadLDAP(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p;

	/* Read NIS setup. */
	fp = fopen(SYSCONFDIR "/ldap.conf", "r");
	if(fp == NULL) {
		return FALSE;
	}

	memset(buf, '\0', sizeof(buf));
	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for(p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* Is it a "base" statement? */
		if(strncmp("base", p, 4) == 0) {
			/* Skip intervening whitespace. */
			for(p += 4; (isspace(*p) && (*p != '\0')); p++);

			/* Save the base DN. */
			if(*p != '\0') {
				info->ldapBaseDN = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Is it a "host" statement? */
		if(strncmp("host", p, 4) == 0) {
			/* Skip intervening whitespace. */
			for(p += 4; (isspace(*p) && (*p != '\0')); p++);

			/* Save the host name or IP. */
			if(*p != '\0') {
				info->ldapServer = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		memset(buf, '\0', sizeof(buf));
	}

	fclose(fp);
	return TRUE;
}

/* Read Kerberos setup from /etc/krb5.conf. */
gboolean authInfoReadKerberos(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p, *q;
	char *section = NULL;
	char *subsection = NULL;

	fp = fopen(SYSCONFDIR "/krb5.conf", "r");
	if(fp == NULL) {
		return FALSE;
	}

	memset(buf, '\0', sizeof(buf));

	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for(p = buf; (isspace(*p) && (*p != '\0')); p++);

		/* If it's a new section, note which one we're "in". */
		if(p[0] == '[') {
			p++;
			for(q = p; ((*q != ']') && (*q != '\0')); q++);

			if(section != NULL) {
				g_free(section);
			}
			if(subsection != NULL) {
				g_free(subsection);
				subsection = NULL;
			}
			if(q - p > 0)  {
				section = g_strndup(p, q - p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the default realm keyword. */
		if(section != NULL)
		if(strcmp(section, "libdefaults") == 0)
		if(strncmp(p, "default_realm", 13) == 0) {
			/* Skip intervening whitespace and the equal sign. */
			for(p += 13;
			    ((isspace(*p) || (*p == '=')) && (*p != '\0'));
			    p++);

			/* Save the default realm. */
			if(*p != '\0') {
				info->kerberosRealm = g_strdup(p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the section about the current realm. */
		if(section != NULL)
		if(strcmp(section, "realms") == 0)
		if(subsection == NULL) {
			/* Read the name of the realm. */
			for(q = p; (!isspace(*q) && (*q != '\0')); q++);

			if(q - p > 0)  {
				subsection = g_strndup(p, q - p);
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Check for the end of a realm section. */
		if(section != NULL)
		if(strcmp(section, "realms") == 0)
		if(subsection != NULL)
		if(strncmp(p, "}", 1) == 0) {
			if(subsection != NULL) {
				g_free(subsection);
				subsection = NULL;
			}

			memset(buf, '\0', sizeof(buf));
			continue;
		}

		/* Values within the current realm. */
		if(section != NULL)
		if(strcmp(section, "realms") == 0)
		if(subsection != NULL)
		if(info->kerberosRealm != NULL)
		if(strcmp(subsection, info->kerberosRealm) == 0) {
			char **target = NULL, *tmp;

			/* See if this is a key we care about. */
			if(strncmp(p, "kdc", 3) == 0) {
				target = &info->kerberosKDC;
				p += 3;
			}
			if(strncmp(p, "admin_server", 12) == 0) {
				target = &info->kerberosAdminServer;
				p += 12;
			}
			if(target == NULL) {
				memset(buf, '\0', sizeof(buf));
				continue;
			}

			/* Skip over the variable and the equal sign. */
			while((isspace(*p) || (*p == '=')) && (*p != '\0')) p++;

			/* Append if we need to, else make a fresh string. */
			if((*target != NULL) && (*p != '\0')) {
				tmp = g_malloc0(strlen(p) + strlen(*target) + 2);
				sprintf(tmp, "%s,%s", *target, p);
				g_free(*target);
				*target = tmp;
			}
			if((*target == NULL) && (*p != '\0')) {
				*target = g_strdup(p);
			}
			memset(buf, '\0', sizeof(buf));
			continue;
		}

		memset(buf, '\0', sizeof(buf));
	}

	return TRUE;
}

/* Read NSS setup from /etc/nsswitch.conf. */
gboolean authInfoReadNSS(struct authInfoType *info)
{
	FILE *fp = NULL;
	char buf[LINE_MAX], *p;
	char *nss_config = NULL;

	/* Read NIS setup. */
	fp = fopen(SYSCONFDIR "/nsswitch.conf", "r");
	if(fp == NULL) {
		return FALSE;
	}

	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);

		/* Snip off the terminating junk. */
		while((p > buf) && (isspace(p[-1]) || (p[-1] == '\n'))) {
			p[-1] = '\0';
			p--;
		}

		/* Skip initial whitespace. */
		for(p = buf; (isspace(*p) && (*p != '\0')); p++);

		if(strncmp("passwd:", buf, 7) == 0) {
			/* Skip the keyword and whitespace. */
			for(p += 7; (isspace(*p) && (*p != '\0')); p++);
			if(*p != '\0') {
				nss_config = g_strdup(p);
			}
		}
	}

	if(nss_config == NULL) {
		nss_config = g_strdup(NSS_DEFAULT);
	}

	info->enableHesiod = (strstr(nss_config, "hesiod") != NULL);
	info->enableLDAP = (strstr(nss_config, "ldap") != NULL);
	info->enableNIS = ((strstr(nss_config, "nis") != NULL) &&
			   ((strstr(nss_config, "nis"))[3] != 'p'));

	g_free(nss_config);
	return TRUE;
}

/* Read hints from the PAM control file. */
gboolean authInfoReadPAM(struct authInfoType *authInfo)
{
	char ibuf[LINE_MAX];
	char module[PATH_MAX];
	char flags[PATH_MAX];
	char *p, *q;
	FILE *fp;

	fp = fopen(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, "r");
	if(fp == NULL) {
		return FALSE;
	}

	while(fgets(ibuf, sizeof(ibuf), fp) != NULL) {
		memset(module, '\0', sizeof(module));
		memset(flags, '\0', sizeof(flags));

		q = ibuf + strlen(ibuf);
		while((q > ibuf) && ((q[-1] == '\n') || (q[-1] == '\r'))) {
			q[-1] = '\0';
			q--;
		}

		p = ibuf;
		for(q = p; !isspace(*q) && (*q != '\0'); q++); /* stack */
		if(strncmp(p, "auth", 4) != 0) {
			continue;
		}

		for(p = q; isspace(*p) && (*p != '\0'); p++);
		for(q = p; !isspace(*q) && (*q != '\0'); q++); /* control */

		for(p = q; isspace(*p) && (*p != '\0'); p++);
		for(q = p; !isspace(*q) && (*q != '\0'); q++); /* module */
		if(q - p < sizeof(module)) {
			strncpy(module, p, q - p);
			if(strstr(module, "pam_krb5")) {
				authInfo->enableKerberos = TRUE;
				continue;
			}
			if(strstr(module, "pam_ldap")) {
				authInfo->enableLDAPAuth = TRUE;
				continue;
			}
		}

		for(p = q; isspace(*p) && (*p != '\0'); p++);
		for(q = p; !isspace(*q) && (*q != '\0'); q++); /* flags */
		if(q - p < sizeof(module)) {
			if(strstr(module, "pam_unix") ||
			   strstr(module, "pam_pwdb")) {
				authInfo->enableMD5 =
					(strstr(p, "md5") != NULL);
				authInfo->enableShadow =
					(strstr(p, "shadow") != NULL);
			}
		}
	}

	fclose(fp);

	return TRUE;
}

/* Read hints from the PAM control file. */
gboolean authInfoReadNetwork(struct authInfoType *authInfo)
{
	shvarFile *sv = NULL;
	char *tmp = NULL;

	sv = svNewFile(SYSCONFDIR "/sysconfig/network");
	if(sv == NULL) {
		return FALSE;
	}

	if((tmp = svGetValue(sv, "NISDOMAIN")) != NULL) {
		if(authInfo->nisDomain) g_free(authInfo->nisDomain);
		authInfo->nisDomain = g_strdup(tmp);
		free(tmp);
	}

	svCloseFile(sv);

	return TRUE;
}

struct authInfoType *authInfoRead()
{
	struct authInfoType *ret = NULL;

	ret = g_malloc0(sizeof(struct authInfoType));

	authInfoReadHesiod(ret);
	authInfoReadNIS(ret);
	authInfoReadLDAP(ret);
	authInfoReadKerberos(ret);
	authInfoReadNSS(ret);
	authInfoReadPAM(ret);
	authInfoReadNetwork(ret);

	return ret;
}

gboolean authInfoWriteHesiod(struct authInfoType *info)
{
	shvarFile *sv = NULL;

	if((sv = svNewFile(SYSCONFDIR "/hesiod.conf")) == NULL) {
		sv = svCreateFile(SYSCONFDIR "/hesiod.conf");
	}

	if(sv == NULL) {
		return FALSE;
	}

	svSetValue(sv, "lhs", info->hesiodLHS);
	svSetValue(sv, "rhs", info->hesiodRHS);
	svWriteFile(sv, 0644);
	svCloseFile(sv);

	return TRUE;
}

static gboolean non_empty(const char *string)
{
	return (string != NULL) && (strlen(string) > 0);
}
static gboolean is_empty(const char *string)
{
	return (string == NULL) || (strlen(string) == 0);
}

/* Write NIS setup to /etc/yp.conf. */
gboolean authInfoWriteNIS(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean written = FALSE;

	fd = open(SYSCONFDIR "/yp.conf", O_RDWR | O_CREAT, 0644);
	if(fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if(fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
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
	while(*p != '\0') {
		/* Isolate a single line. */
		for(q = p; (*q != '\0') && (*q != '\n'); q++);
		if(*q != '\0') q++;

		/* If it's a 'domain' line, insert ours instead. */
		if(strncmp("domain", p, 6) == 0) {
			if(!written)
			if(non_empty(info->nisDomain)) {
				strcat(obuf, "domain ");
				strcat(obuf, info->nisDomain);
				/* Take an empty server name to mean that we
				 * want to use broadcast. */
				if(non_empty(info->nisServer)) {
					strcat(obuf, " server ");
					strcat(obuf, info->nisServer);
				} else {
					strcat(obuf, " broadcast");
				}
				strcat(obuf, "\n");

				written = TRUE;
			}
		} else

		/* If it's a 'ypserver' line, insert ours instead. */
		if(strncmp("ypserver", p, 8) == 0) {
			if(!written)
			if(is_empty(info->nisDomain))
			if(non_empty(info->nisServer)) {
				strcat(obuf, "ypserver ");
				strcat(obuf, info->nisServer);
				strcat(obuf, "\n");
				written = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered a domain line yet... */
	if(!written) {
		if(non_empty(info->nisDomain)) {
			strcat(obuf, "domain ");
			strcat(obuf, info->nisDomain);
			if(non_empty(info->nisServer)) {
				strcat(obuf, " server ");
				strcat(obuf, info->nisServer);
			} else {
				strcat(obuf, " broadcast");
			}
			strcat(obuf, "\n");
		} else {
			if(non_empty(info->nisServer)) {
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

/* Write LDAP setup to /etc/ldap.conf. */
gboolean authInfoWriteLDAP(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wrotebasedn = FALSE, wroteserver = FALSE;

	fd = open(SYSCONFDIR "/ldap.conf", O_RDWR | O_CREAT, 0644);
	if(fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if(fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen(" host ") + strlen(" base ");
	l += info->ldapBaseDN ? strlen(info->ldapBaseDN) : 0;
	l += info->ldapServer ? strlen(info->ldapServer) : 0;
	obuf = g_malloc0(st.st_size + 1 + l);

	p = ibuf;
	while(*p != '\0') {
		/* Isolate a single line. */
		for(q = p; (*q != '\0') && (*q != '\n'); q++);
		if(*q != '\0') q++;

		/* If it's a 'server' line, insert ours instead. */
		if(strncmp("host ", p, 4) == 0) {
			if(!wroteserver)
			if(non_empty(info->ldapServer)) {
				strcat(obuf, "host ");
				strcat(obuf, info->ldapServer);
				strcat(obuf, "\n");
				wroteserver = TRUE;
			}
		} else

		/* If it's a 'base' line, insert ours instead. */
		if(strncmp("base", p, 4) == 0) {
			if(!wrotebasedn)
			if(non_empty(info->ldapBaseDN)) {
				strcat(obuf, "base ");
				strcat(obuf, info->ldapBaseDN);
				strcat(obuf, "\n");
				wrotebasedn = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered either of the config lines yet... */
	if(!wroteserver) {
		if(non_empty(info->ldapServer)) {
			strcat(obuf, "host ");
			strcat(obuf, info->ldapServer);
			strcat(obuf, "\n");
		}
	}
	if(!wrotebasedn) {
		if(non_empty(info->ldapBaseDN)) {
			strcat(obuf, "base ");
			strcat(obuf, info->ldapBaseDN);
			strcat(obuf, "\n");
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

static void write_kdc(char *obuf, struct authInfoType *info)
{
	char *p = info->kerberosKDC;
	if(is_empty(p))
		return;
	while(strchr(p, ',')) {
		strcat(obuf, "  kdc = ");
		strncat(obuf, p, strchr(p, ',') - p);
		p = strchr(p, ',') + 1;
		strcat(obuf, "\n");
	}
	strcat(obuf, "  kdc = ");
		strcat(obuf, p);
	strcat(obuf, "\n");
}

static void write_admin_server(char *obuf, struct authInfoType *info)
{
	char *p = info->kerberosAdminServer;
	if(is_empty(p))
		return;
	while(strchr(p, ',')) {
		strcat(obuf, "  admin_server = ");
		strncat(obuf, p, strchr(p, ',') - p);
		p = strchr(p, ',') + 1;
		strcat(obuf, "\n");
	}
	strcat(obuf, "  admin_server = ");
		strcat(obuf, p);
	strcat(obuf, "\n");
}

static void write_realm(char *obuf, struct authInfoType *info)
{
	strcat(obuf, " ");
	strcat(obuf, info->kerberosRealm);
	strcat(obuf, " = {\n");
	write_kdc(obuf, info);
	write_admin_server(obuf, info);
	strcat(obuf, " }\n");
	strcat(obuf, "\n");
}

static int comma_count(const char *string)
{
	int ret = 0;
	for(;string && (*string != '\0'); string++) {
		if(*string == ',') {
			ret++;
		}
	}
	return ret;
}

/* Write Kerberos 5 setup to /etc/krb5.conf. */
gboolean authInfoWriteKerberos(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	gboolean wrotekdc = FALSE, wroterealm = FALSE, wroteadmin = FALSE;
	gboolean wroterealms = FALSE, wrotelibdefaults = FALSE;
	gboolean wrotedefaultrealm = FALSE;
	char *section = NULL, *subsection = NULL;

	fd = open(SYSCONFDIR "/krb5.conf", O_RDWR | O_CREAT, 0644);
	if(fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if(fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
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
	while(*p != '\0') {
		/* Isolate a single line. */
		char *l = p;
		for(q = p; (*q != '\0') && (*q != '\n'); q++);
		if(*q != '\0') q++;

		/* Skip over any whitespace. */
		for(;isspace(*p) && (*p != '\0') && (*p != '\n'); p++);

		/* If this is the "kdc" in our realm, replace it with
		 * the values we now have. */
		if((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection != NULL) &&
		   (non_empty(info->kerberosRealm)) &&
		   (strcmp(subsection, info->kerberosRealm) == 0) &&
		   (strncmp(p, "kdc", 3) == 0)) {
			if(!wrotekdc)
			if(info->kerberosKDC) {
				write_kdc(obuf, info);
				wrotekdc = TRUE;
			}
			p = q;
			continue;
		}

		/* If this is the "admin_server" in our realm, replace it with
		 * the values we now have. */
		if((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection != NULL) &&
		   (non_empty(info->kerberosRealm)) &&
		   (strcmp(subsection, info->kerberosRealm) == 0) &&
		   (strncmp(p, "admin_server", 3) == 0)) {
			if(!wroteadmin)
			if(info->kerberosAdminServer) {
				write_admin_server(obuf, info);
				wroteadmin = TRUE;
			}
			p = q;
			continue;
		}

		/* If we're in the realms section, but not in a realm, we'd
		 * better be looking at the beginning of one. */
		if((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
		   (subsection == NULL)) {
			char *q;
			for(q = p; !isspace(*q) && (*q != '\0'); q++);
			if(subsection) {
				g_free(subsection);
			}
			subsection = g_strndup(p, q - p);
			/* If this is the section for our realm, mark that. */
			if(strcmp(subsection, info->kerberosRealm) == 0) {
				wroterealm = TRUE;
			}
		}

		/* If it's the end of a subsection, mark that. */
		if((section != NULL) &&
		   (strcmp(section, "realms") == 0) &&
	   	   (subsection != NULL) &&
		   (strncmp(p, "}", 1) == 0)) {
			/* If it's the right section of realms, write out
			 * info we haven't already written. */
	   	   	if(non_empty(info->kerberosRealm) &&
	   	   	   (strcmp(subsection, info->kerberosRealm) == 0)) {
				if(!wrotekdc) {
					write_kdc(obuf, info);
				}
				if(!wroteadmin) {
					write_admin_server(obuf, info);
				}
			}
			if(subsection) {
				g_free(subsection);
			}
			subsection = NULL;
		}

		/* If we're in the libdefaults section, and this is the
		 * default_realm keyword, replace it with ours. */
		if((section != NULL) &&
		   (strcmp(section, "libdefaults") == 0) &&
		   (strncmp(p, "default_realm", 13) == 0)) {
			if(!wrotedefaultrealm) {
				strcat(obuf, " default_realm = ");
				strcat(obuf, info->kerberosRealm);
				strcat(obuf, "\n");
				wrotedefaultrealm = TRUE;
			}
			p = q;
			continue;
		}

		/* If it's the beginning of a section, record its name. */
		if(strncmp("[", p, 1) == 0) {
			char *q;
			p++;
			/* If the previous section was "realms", and we didn't
			 * see ours, write our realm out. */
			if((section != NULL) &&
			   (strcmp(section, "realms") == 0) &&
			   !wroterealm) {
				write_realm(obuf, info);
				wroterealm = TRUE;
			}
			/* If the previous section was "libdefaults", and we
			 * didn't see a "default_realm", write it out. */
			if((section != NULL) &&
			   (strcmp(section, "libdefaults") == 0) &&
			   !wrotedefaultrealm) {
				strcat(obuf, " default_realm = ");
				strcat(obuf, info->kerberosRealm);
				strcat(obuf, "\n");
				wrotedefaultrealm = TRUE;
			}
			for(q = p; ((*q != ']') && (*q != '\0')); q++);
			if(section) {
				g_free(section);
			}
			section = g_strndup(p, q - p);
			if(strcmp(section, "realms") == 0) {
				wroterealms = TRUE;
			}
			if(strcmp(section, "libdefaults") == 0) {
				wrotelibdefaults = TRUE;
			}
		}

		/* Otherwise, just copy the current line out. */
		strncat(obuf, l, q - l);
		p = q;
	}

	/* If we haven't encountered a libdefaults section yet... */
	if(!wrotelibdefaults && non_empty(info->kerberosRealm)) {
		strcat(obuf, "[libdefaults]\n");
		strcat(obuf, " default_realm = ");
		strcat(obuf, info->kerberosRealm);
		strcat(obuf, "\n\n");
	}

	/* If we haven't encountered a realms section yet... */
	if(!wroterealms && non_empty(info->kerberosRealm)) {
		strcat(obuf, "[realms]\n");
		write_realm(obuf, info);
	}

	/* Write it out and close it. */
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	close(fd);

	/* Clean up. */
	if(ibuf) {
		g_free(ibuf);
	}
	if(obuf) {
		g_free(obuf);
	}
	if(section) {
		g_free(section);
	}
	if(subsection) {
		g_free(subsection);
	}

	return TRUE;
}

/* Write NSS setup to /etc/nsswitch.conf. */
gboolean authInfoWriteNSS(struct authInfoType *info)
{
	char *ibuf = NULL, *obuf = NULL, *p, *q;
	int fd, l;
	struct stat st;
	struct flock lock;
	char buf[LINE_MAX] = "";
	gboolean wrotepasswd = FALSE, wrotegroup = FALSE, wroteshadow = FALSE;

	fd = open(SYSCONFDIR "/nsswitch.conf", O_RDWR|O_CREAT, 0644);
	if(fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if(fcntl(fd, F_SETLKW, &lock) == -1) {
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
		return FALSE;
	}

	/* Read in the old file. */
	ibuf = g_malloc0(st.st_size + 1);
	read(fd, ibuf, st.st_size);

	/* Determine the maximum length of the new file. */
	l = strlen("passwd:     \n") +
	    strlen("shadow:     \n") +
	    strlen("group:      \n");
	l += strlen(NSS_DEFAULT) * 3;
	l += strlen(" files") * 3;
	l += strlen(" hesiod") * 3;
	l += strlen(" ldap") * 3;
	l += strlen(" nis") * 3;
	obuf = g_malloc0(st.st_size + 1 + l);

	/* Determine what we want in that file. */
	strcpy(buf, "files");
	if(info->enableHesiod) strcat(buf, " hesiod");
	if(info->enableLDAP) strcat(buf, " ldap");
	if(info->enableNIS) strcat(buf, " nis");
	if(!info->enableHesiod && !info->enableLDAP && !info->enableNIS) {
		strcpy(buf, NSS_DEFAULT);
	}

	p = ibuf;
	while(*p != '\0') {
		/* Isolate a single line. */
		for(q = p; (*q != '\0') && (*q != '\n'); q++);
		if(*q != '\0') q++;

		/* If it's a 'passwd' line, insert ours instead. */
		if(strncmp("passwd:", p, 7) == 0) {
			if(!wrotepasswd) {
				strcat(obuf, "passwd:     ");
				strcat(obuf, buf);
				strcat(obuf, "\n");
				wrotepasswd = TRUE;
			}
		} else

		/* If it's a 'shadow' line, insert ours instead. */
		if(strncmp("shadow:", p, 7) == 0) {
			if(!wroteshadow) {
				strcat(obuf, "shadow:     ");
				strcat(obuf, buf);
				strcat(obuf, "\n");
				wroteshadow = TRUE;
			}
		} else

		/* If it's a 'group' line, insert ours instead. */
		if(strncmp("group:", p, 6) == 0) {
			if(!wrotegroup) {
				strcat(obuf, "group:      ");
				strcat(obuf, buf);
				strcat(obuf, "\n");
				wrotegroup = TRUE;
			}
		} else

		/* Otherwise, just copy the current line out. */
		strncat(obuf, p, q - p);
		p = q;
	}

	/* If we haven't encountered any of the config lines yet... */
	if(!wrotepasswd) {
		strcat(obuf, "passwd:     ");
		strcat(obuf, buf);
		strcat(obuf, "\n");
	}
	if(!wroteshadow) {
		strcat(obuf, "shadow:     ");
		strcat(obuf, buf);
		strcat(obuf, "\n");
	}
	if(!wrotegroup) {
		strcat(obuf, "group:      ");
		strcat(obuf, buf);
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

static const char *argv_krb5_auth[] = {
	"use_first_pass",
	NULL,
};

static const char *argv_krb5afs_auth[] = {
	"use_first_pass",
	"tokens",
	NULL,
};

static const char *argv_krb5_password[] = {
	"use_authtok",
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

static const char *argv_cracklib_password[] = {
	"retry=3",
	NULL,
};

/* Enumerations for PAM control flags and stack names. */
enum pam_function_type {
	auth,
	account,
	session,
	password,
};
enum pam_logic_type {
	skip,
	sufficient,
	required,
	optional,
};

/* The list of stacks, module flags, and arguments, if there are any. */
static struct {
	gboolean mandatory;
	enum pam_function_type stack;
	enum pam_logic_type logic;
	const char *name;
	const char **argv;
} standard_pam_modules[] = {
	{TRUE,  auth,		sufficient,	"unix",		argv_unix_auth},
	{FALSE, auth,		sufficient,	"krb5",		argv_krb5_auth},
	{FALSE, auth,		sufficient,	"krb5afs",	argv_krb5afs_auth},
	{FALSE, auth,		sufficient,	"ldap",		argv_ldap_auth},
#ifdef WINBIND
	{FALSE, auth,		sufficient,	"winbind",	NULL},
#endif
	{TRUE,  auth,		required,	"deny",		NULL},

	{TRUE,  account,	sufficient,	"unix",		NULL},
	{FALSE, account,	sufficient,	"ldap",		NULL},
	{TRUE,  account,	required,	"deny",		NULL},

	{TRUE,  password,	required,	"cracklib",
	 argv_cracklib_password},
	{TRUE,  password,	sufficient,	"unix",
	 argv_unix_password},
	{FALSE, password,	sufficient,	"krb5",
	 argv_krb5_password},
	{FALSE, password,	sufficient,	"krb5afs",
	 argv_krb5_password},
	{FALSE, password,	sufficient,	"ldap",
	 argv_ldap_password},
#ifdef WINBIND
	{FALSE, password,	sufficient,	"winbind",	NULL},
#endif
	{TRUE,  password,	required,	"deny",		NULL},

	{TRUE,  session,	required,	"unix",		NULL},
	{FALSE, session,	optional,	"krb5",		NULL},
	{FALSE, session,	optional,	"krb5afs",	NULL},
	{FALSE, session,	optional,	"ldap",		NULL},
#ifdef WINBIND
	{FALSE, session,	optional,	"winbind",	NULL},
#endif
};

static void fmt_standard_pam_module(int i, char *obuf, struct authInfoType *info)
{
	char *stack, *logic;
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
	switch(standard_pam_modules[i].logic) {
		case skip:
			logic = "";
			break;
		case required:
			logic = "required";
			break;
		case sufficient:
			logic = "sufficient";
			break;
		case optional:
			logic = "optional";
			break;
		default:
			logic = NULL;
			break;
	}
	if(non_empty(stack) && non_empty(logic)) {
		if(strlen(logic) > 0) {
			int j;
			char buf[LINE_MAX];
			memset(buf, '\0', sizeof(buf));
			snprintf(buf, sizeof(buf) - 1, "%-12s%-14s%s/pam_%s.so",
				 stack, logic, AUTH_MODULE_DIR,
				 standard_pam_modules[i].name);
			if(standard_pam_modules[i].argv != NULL) {
				for(j = 0;
				    non_empty(standard_pam_modules[i].argv[j]);
				    j++) {
					strncat(buf, " ",
						sizeof(buf) - 1 - strlen(buf));
					strncat(buf,
						standard_pam_modules[i].argv[j],
						sizeof(buf) - 1 - strlen(buf));
				}
			}
			if(strcmp(standard_pam_modules[i].name, "unix") == 0)
			if(stack != NULL)
			if((strcmp(stack, "auth") == 0) ||
			   (strcmp(stack, "password") == 0)) {
				if(info->enableMD5) {
					strncat(buf, " md5",
						sizeof(buf) - 1 - strlen(buf));
				}
				if(info->enableShadow) {
					strncat(buf, " shadow",
						sizeof(buf) - 1 - strlen(buf));
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

	fd = open(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, O_RDWR|O_CREAT, 0644);
	if(fd == -1) {
		return FALSE;
	}

	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	if(fcntl(fd, F_SETLKW, &lock) == -1) {
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

	for(i = 0;
	    i < sizeof(standard_pam_modules) / sizeof(standard_pam_modules[0]);
	    i++) {
		if(standard_pam_modules[i].mandatory ||
		   (authInfo->enableKerberos && !have_afs &&
		    (strcmp("krb5", standard_pam_modules[i].name) == 0)) ||
		   (authInfo->enableKerberos && have_afs &&
		    (strcmp("krb5afs", standard_pam_modules[i].name) == 0)) ||
#ifdef WINBIND
		   (authInfo->enableWinBindAuth &&
		    (strcmp("winbind", standard_pam_modules[i].name) == 0)) ||
#endif
		   (authInfo->enableLDAPAuth &&
		    (strcmp("ldap", standard_pam_modules[i].name) == 0))) {
			fmt_standard_pam_module(i, obuf, authInfo);
		}
	}

	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	write(fd, obuf, strlen(obuf));
	g_free(obuf);
	close(fd);

	return TRUE;
}

gboolean authInfoWriteNetwork(struct authInfoType *info)
{
	shvarFile *sv = NULL;

	if((sv = svNewFile(SYSCONFDIR "/sysconfig/network")) == NULL) {
		sv = svCreateFile(SYSCONFDIR "/sysconfig/network");
	};
	if(sv == NULL) {
		return FALSE;
	}

	svSetValue(sv, "NISDOMAIN", info->nisDomain);
	svWriteFile(sv, 0644);
	svCloseFile(sv);
	return TRUE;
}

gboolean authInfoWrite(struct authInfoType *authInfo)
{
	gboolean ret = TRUE;
	ret = ret && authInfoWriteKerberos(authInfo);
	ret = ret && authInfoWriteHesiod(authInfo);
	ret = ret && authInfoWriteNIS(authInfo);
	ret = ret && authInfoWriteLDAP(authInfo);
	ret = ret && authInfoWriteNSS(authInfo);
	ret = ret && authInfoWritePAM(authInfo);
	ret = ret && authInfoWriteNetwork(authInfo);
	return ret;
}
