/*
 * Authconfig - authentication configuration program
 * Copyright (c) 1999, 2000 Red Hat, Inc.
 *
 * This program is licensed under the terms of the GPL.
 */

#ifndef authinfo_h
#define authinfo_h

#define SYSCONFDIR "/etc"
#define AUTH_PAM_SERVICE "system-auth"
#define AUTH_MODULE_DIR "/lib/security"
#define NSS_DEFAULT "files nisplus nis"

#define PATH_YPBIND "/sbin/ypbind"
#define PATH_LIBNSS_LDAP "/lib/libnss_ldap.so.2"
#define PATH_LIBNSS_NIS "/lib/libnss_nis.so.2"
#define PATH_PAM_KRB5 "/lib/security/pam_krb5.so"
#define PATH_PAM_LDAP "/lib/security/pam_ldap.so"

#define i18n(String) gettext((String))

/*
 * used to hold information regarding different authentication
 * methods.  Add fields here if you add another type.  Even though
 * some of these fields are "common" across different authentication
 * types, we want to hold all the information so that if a user toggles
 * between the various types, the form can be pre-populated with the
 * information read from system configuration files.
 */
struct authInfoType {
	/* Service-specific settings. */
	char *hesiodLHS;
	char *hesiodRHS;
  
	char *ldapServer;
	char *ldapBaseDN;

	char *kerberosRealm;
	char *kerberosKDC;
	char *kerberosAdminServer;

	char *nisServer;
	char *nisDomain;
  
	/* NSSwitch setup.  Files is always in there. */
	gboolean enableHesiod;
	gboolean enableLDAP;
	gboolean enableNIS;

	/* Authentication setup. */
	gboolean enableMD5;
	gboolean enableShadow;
	gboolean enableKerberos;
	gboolean enableLDAPAuth;
};

struct authInfoType *authInfoRead();
gboolean authInfoWrite(struct authInfoType *authInfo);

gboolean authInfoReadHesiod(struct authInfoType *info);
gboolean authInfoReadNIS(struct authInfoType *info);
gboolean authInfoReadLDAP(struct authInfoType *info);
gboolean authInfoReadKerberos(struct authInfoType *info);
gboolean authInfoReadNSS(struct authInfoType *info);
gboolean authInfoReadPAM(struct authInfoType *info);
gboolean authInfoReadNetwork(struct authInfoType *authInfo);

gboolean authInfoWriteHesiod(struct authInfoType *info);
gboolean authInfoWriteNIS(struct authInfoType *info);
gboolean authInfoWriteLDAP(struct authInfoType *info);
gboolean authInfoWriteKerberos(struct authInfoType *info);
gboolean authInfoWriteNSS(struct authInfoType *info);
gboolean authInfoWritePAM(struct authInfoType *info);
gboolean authInfoWriteNetwork(struct authInfoType *info);

#endif
