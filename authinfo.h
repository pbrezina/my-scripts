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

#ifndef authinfo_h
#define authinfo_h

#define SYSCONFDIR "/etc"
#define AUTH_PAM_SERVICE "system-auth"
#define AUTH_MODULE_DIR "/lib/security/$ISA"

#define PATH_PORTMAP "/sbin/portmap"
#define PATH_PWCONV "/usr/sbin/pwconv"
#define PATH_NSCD "/usr/sbin/nscd"
#define PATH_NSCD_PID "/var/run/nscd.pid"
#define PATH_DBBIND "/usr/sbin/dbbind"
#define PATH_DBBIND_PID "/var/run/dbbind.pid"
#define PATH_DBIBIND "/usr/sbin/dbibind"
#define PATH_DBIBIND_PID "/var/run/dbibind.pid"
#define PATH_HESIODBIND "/usr/sbin/hesiodbind"
#define PATH_HESIODBIND_PID "/var/run/hesiodbind.pid"
#define PATH_LDAPBIND "/usr/sbin/ldapbind"
#define PATH_LDAPBIND_PID "/var/run/ldapbind.pid"
#define PATH_ODBCBIND "/usr/sbin/odbcbind"
#define PATH_ODBCBIND_PID "/var/run/odbcbind.pid"
#define PATH_WINBIND "/usr/sbin/winbindd"
#define PATH_WINBIND_PID "/var/run/winbindd.pid"
#define PATH_YPBIND "/sbin/ypbind"
#define PATH_YPBIND_PID "/var/run/ypbind.pid"
#define PATH_SEBOOL "/usr/sbin/setsebool"

#ifdef PREFER_LIB64
#define LIBDIR "/lib64"
#else
#define LIBDIR "/lib"
#endif

#define PATH_LIBNSS_DB LIBDIR "/libnss_db.so.2"
#define PATH_LIBNSS_LDAP LIBDIR "/libnss_ldap.so.2"
#define PATH_LIBNSS_NIS LIBDIR "/libnss_nis.so.2"
#define PATH_LIBNSS_ODBCBIND LIBDIR "/libnss_odbcbind.so.2"
#define PATH_LIBNSS_WINBIND LIBDIR "/libnss_winbind.so.2"
#define PATH_LIBNSS_WINS LIBDIR "/libnss_wins.so.2"

#define PATH_PAM_KRB5 LIBDIR "/security/pam_krb5.so"
#define PATH_PAM_LDAP LIBDIR "/security/pam_ldap.so"
#define PATH_PAM_SMB LIBDIR "/security/pam_smb_auth.so"
#define PATH_PAM_WINBIND LIBDIR "/security/pam_winbind.so"

#define PATH_WINBIND_NET "/usr/bin/net"

#define PATH_LDAP_CACERTS "/etc/openldap/cacerts"

#define _(String) gettext((String))
#define AUTHCONFIG_PACKAGE_WARNING _("The %s file was not found, but it is "\
        "required for %s support to work properly.  Install the %s package, "\
        "which provides this file.")

struct authInfoPrivate;

/*
 * used to hold information regarding different authentication
 * methods.  Add fields here if you add another type.  Even though
 * some of these fields are "common" across different authentication
 * types, we want to hold all the information so that if a user toggles
 * between the various types, the form can be pre-populated with the
 * information read from system configuration files.
 */
struct authInfoType {
	struct authInfoPrivate *pvt;

	/* Service-specific settings. */
	char *hesiodLHS;
	char *hesiodRHS;
  
	char *ldapServer;
	char *ldapBaseDN;

	char *kerberosRealm;
	gboolean kerberosRealmviaDNS;
	char *kerberosKDC;
	gboolean kerberosKDCviaDNS;
	char *kerberosAdminServer;

	char *nisServer;
	char *nisDomain;

	char *smbWorkgroup;
	char *smbRealm;
	char *smbServers;
	char *smbSecurity;
	char *smbIdmapUid;
	char *smbIdmapGid;

	char *winbindSeparator;
	char *winbindTemplateHomedir;
	char *winbindTemplatePrimaryGroup;
	char *winbindTemplateShell;
	gboolean winbindUseDefaultDomain;

	/* NSSwitch setup.  Files is always in there. */
	gboolean enableCache;
	gboolean enableCompat;
	gboolean enableDB;
	gboolean enableDirectories;
	gboolean enableHesiod;
	gboolean enableLDAP;
	gboolean enableLDAPS;
	gboolean enableNIS;
	gboolean enableNIS3;
	gboolean enableDBbind;
	gboolean enableDBIbind;
	gboolean enableHesiodbind;
	gboolean enableLDAPbind;
	gboolean enableOdbcbind;
	gboolean enableWinbind;
	gboolean enableWINS;

	/* Authentication setup. */
	gboolean enableAFS;
	gboolean enableAFSKerberos;
	gboolean enableBigCrypt;
	gboolean enableCracklib;
	gboolean enableEPS;
	gboolean enableKerberos;
	gboolean enableLDAPAuth;
	gboolean enableMD5;
	gboolean enableOTP;
	gboolean enablePasswdQC;
	gboolean enableShadow;
	gboolean enableSMB;
	gboolean enableWinbindAuth;
	gboolean enableLocAuthorize;

#ifdef LOCAL_POLICIES
	gboolean enableLocal;
#endif
	gboolean brokenShadow;
	gboolean forceBrokenShadow;

	/* Not really options. */
	char *joinUser, *joinPassword;
	char *cracklibArgs;
	char *passwdqcArgs;
	char *localuserArgs;
	char *ldapCacertDir;
};

struct authInfoType *authInfoRead(void);
void authInfoFree(struct authInfoType *info);
struct authInfoType *authInfoProbe(void);
gboolean authInfoDiffers(struct authInfoType *a, struct authInfoType *b);
struct authInfoType *authInfoCopy(struct authInfoType *info);
gboolean authInfoWrite(struct authInfoType *info);

gboolean authInfoReadCache(struct authInfoType *info);
gboolean authInfoReadHesiod(struct authInfoType *info);
gboolean authInfoReadNIS(struct authInfoType *info);
gboolean authInfoReadSMB(struct authInfoType *info);
gboolean authInfoReadLDAP(struct authInfoType *info);
gboolean authInfoReadKerberos(struct authInfoType *info);
gboolean authInfoReadNSS(struct authInfoType *info);
gboolean authInfoReadPAM(struct authInfoType *info);
gboolean authInfoReadNetwork(struct authInfoType *info);
gboolean authInfoReadWinbind(struct authInfoType *info);

void authInfoUpdate(struct authInfoType *info);

gboolean authInfoWriteCache(struct authInfoType *info);
gboolean authInfoWriteHesiod(struct authInfoType *info);
gboolean authInfoWriteLibuser(struct authInfoType *info);
gboolean authInfoWriteNIS(struct authInfoType *info);
gboolean authInfoWriteSMB(struct authInfoType *info);
gboolean authInfoWriteLDAP(struct authInfoType *info);
gboolean authInfoWriteKerberos(struct authInfoType *info);
gboolean authInfoWriteNSS(struct authInfoType *info);
gboolean authInfoWritePAM(struct authInfoType *info);
gboolean authInfoWriteNetwork(struct authInfoType *info);
gboolean authInfoWriteWinbind(struct authInfoType *info);

void authInfoPost(struct authInfoType *authInfo, int nostart);
void authInfoPrint(struct authInfoType *authInfo);
void authInfoJoin(struct authInfoType *authInfo, gboolean echo);

gboolean authInfoLDAPCACertsTest(struct authInfoType *authInfo);
void authInfoLDAPCACertsRehash(struct authInfoType *authInfo);

#endif
