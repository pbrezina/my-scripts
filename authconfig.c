/*
 * Authconfig - authentication configuration program
 * Author: Preston Brown <pbrown@redhat.com>
 * Copyright (c) 1999, 2000 Red Hat, Inc.
 *
 * This program is licensed under the terms of the GPL.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <newt.h>
#include <popt.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <glib.h>
#include "authinfo.h"

static char *progName;

struct nis_cb {
	newtComponent serverLabel, domainLabel;
	newtComponent serverEntry, domainEntry;
};
struct hesiod_cb {
	newtComponent lhsLabel, rhsLabel;
	newtComponent lhsEntry, rhsEntry;
};
struct ldap_cb {
	newtComponent serverLabel, baseDnLabel;
       	newtComponent serverEntry, baseDnEntry;
};
struct krb5_cb {
	newtComponent realmLabel, kdcLabel, kadminLabel;
	newtComponent realmEntry, kdcEntry, kadminEntry;
};

/*
 * small callback to disallow spaces in an entry field.
 */
int entryFilter(newtComponent entry, void * data, int ch, int cursor)
{
    if ((ch == ' ') || (ch == '\t'))
	return 0;
    return ch;
}

gboolean toggleNisService(gboolean enableNis, char *nisDomain, gboolean nostart)
{
  char *domainStr;
  if (enableNis && (nisDomain != NULL) && (strlen(nisDomain) > 0)) { 
    domainStr = g_strdup_printf("/bin/domainname %s", nisDomain);
    system(domainStr);
    g_free(domainStr);
    if (!nostart) {
      system("/etc/rc.d/init.d/ypbind restart");
    }
    system("/sbin/chkconfig --level 345 ypbind on");
  } else {
    system("/bin/domainname \"(none)\"");
    if (!nostart) {
      system("/etc/rc.d/init.d/ypbind stop");
    }
    system("/sbin/chkconfig --del ypbind");
  }

  return TRUE;
}

gboolean toggleShadow(struct authInfoType *authInfo)
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

void overrideBoolean(gboolean *dest, int source)
{
  *dest = (source != 0) ? TRUE : *dest;
}

void setString(char **dest, const char *source)
{
  if (*dest != NULL) {
    g_free(*dest);
  }
  *dest = g_strdup(source);
}

void overrideString(char **dest, const char *source)
{
  if (source != NULL) {
    setString(dest, source);
  }
}

void enableEntryByCheckbox(newtComponent cb, void *target)
{
  newtEntrySetFlags(target, NEWT_FLAG_DISABLED,
		    newtCheckboxGetValue(cb) == '*' ?
		    NEWT_FLAGS_RESET : NEWT_FLAGS_SET);
}

int getChoices(int back,
	       gboolean nisAvail, gboolean ldapAvail, gboolean kerberosAvail,
	       struct authInfoType *authInfo)
{
  newtComponent form, ok, cancel, comp, label, cb, ldapcb, entry;
  gboolean rc = FALSE;
  char nss_hesiod = 0, nss_ldap = 0, nss_nis = 0;
  char shadow = 0, md5 = 0, pam_krb5 = 0, pam_ldap = 0;
  char *hesiodLHS = NULL, *hesiodRHS = NULL;
  char *ldapServer = NULL, *ldapBaseDN = NULL;
  char *nisServer = NULL, *nisDomain = NULL;
  char *kerberosRealm = NULL, *kerberosKDC = NULL, *kerberosAdmin = NULL;

  /* Create the window and a form to put into it. */
  newtCenteredWindow(70, 19, i18n("Authentication Configuration"));
  form = newtForm(NULL, NULL, 0);

  /* Labels. */
  label = newtLabel(3, 1, i18n("User Information Services"));
  newtFormAddComponent(form, label);
  label = newtLabel(37, 1, i18n("Authentication Services"));
  newtFormAddComponent(form, label);

  /* NSS modules. */
  cb = newtCheckbox(3, 3, i18n("Use NIS"), authInfo->enableNIS ? '*' : ' ',
		    NULL, &nss_nis);
  newtFormAddComponent(form, cb);
  label = newtLabel(3, 4, i18n("  Domain:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 4, authInfo->nisDomain, 20, &nisDomain,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);
  label = newtLabel(3, 5, i18n("  Server:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 5, authInfo->nisServer, 20, &nisServer,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);

  ldapcb = newtCheckbox(3, 7, i18n("Use LDAP"),
		        authInfo->enableLDAP ? '*' : ' ', NULL, &nss_ldap);
  newtFormAddComponent(form, ldapcb);
  label = newtLabel(3, 8, i18n("  Server:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 8, authInfo->ldapServer, 20, &ldapServer,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);
  label = newtLabel(3, 9, i18n(" Base DN:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 9, authInfo->ldapBaseDN, 20, &ldapBaseDN,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);

  cb = newtCheckbox(3, 11, i18n("Use Hesiod"),
		    authInfo->enableHesiod ? '*' : ' ', NULL, &nss_hesiod);
  newtFormAddComponent(form, cb);
  label = newtLabel(3, 12, i18n("     LHS:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 12, authInfo->hesiodLHS, 20, &hesiodLHS,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);
  label = newtLabel(3, 13, i18n("     RHS:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(13, 13, authInfo->hesiodRHS, 20, &hesiodRHS,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);

  /* PAM setup. */
  cb = newtCheckbox(37, 3, i18n("Use Shadow Passwords"),
		    authInfo->enableShadow ? '*' : ' ', NULL, &shadow);
  newtFormAddComponent(form, cb);

  cb = newtCheckbox(37, 5, i18n("Use MD5 Passwords"),
		    authInfo->enableMD5 ? '*' : ' ', NULL, &md5);
  newtFormAddComponent(form, cb);

  ldapcb = newtCheckbox(37, 7, i18n("Use LDAP Authentication"),
		        authInfo->enableLDAPAuth ? '*' : ' ', NULL, &pam_ldap);
  newtFormAddComponent(form, ldapcb);

  cb = newtCheckbox(37, 9, i18n("Use Kerberos"),
		    authInfo->enableKerberos ? '*' : ' ', NULL, &pam_krb5);
  newtFormAddComponent(form, cb);
  label = newtLabel(37, 10, i18n(" Realm:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(45, 10, authInfo->kerberosRealm, 22, &kerberosRealm,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);
  label = newtLabel(37, 11, i18n("   KDC:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(45, 11, authInfo->kerberosKDC, 22, &kerberosKDC,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);
  label = newtLabel(37, 12, i18n(" Admin:"));
  newtFormAddComponent(form, label);
  entry = newtEntry(45, 12, authInfo->kerberosAdminServer, 22, &kerberosAdmin,
		    NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(entry, entryFilter, NULL);
  newtFormAddComponent(form, entry);

  /* Create the buttons. */
  ok = newtButton(20, 15, i18n("Ok"));
  cancel = newtButton(38, 15, back ? i18n("Back") : i18n("Cancel"));
  newtFormAddComponents(form, ok, cancel, NULL);

  /* Run the form and interpret the results. */
  comp = newtRunForm(form);
  if(comp == ok) {
    authInfo->enableHesiod = (nss_hesiod == '*');
    setString(&authInfo->hesiodLHS, hesiodLHS);
    setString(&authInfo->hesiodRHS, hesiodRHS);

    authInfo->enableLDAP = (nss_ldap == '*');
    setString(&authInfo->ldapServer, ldapServer);
    setString(&authInfo->ldapBaseDN, ldapBaseDN);

    authInfo->enableNIS = (nss_nis == '*');
    setString(&authInfo->nisServer, nisServer);
    setString(&authInfo->nisDomain, nisDomain);

    authInfo->enableMD5 = (md5 == '*');
    authInfo->enableShadow = (shadow == '*');

    authInfo->enableKerberos = (pam_krb5 == '*');
    setString(&authInfo->kerberosRealm, kerberosRealm);
    setString(&authInfo->kerberosKDC, kerberosKDC);
    setString(&authInfo->kerberosAdminServer, kerberosAdmin);

    authInfo->enableLDAPAuth = (pam_ldap == '*');

    rc = TRUE;
  }
  newtFormDestroy(form);

  return rc;
}

void usage(void) {
    fprintf(stderr, i18n("Usage: %s [options]\n\n"
			 "     --nostart                  do not start/stop ypbind\n"
			 "     --useshadow                use shadow passwords by default\n"
			 "     --enablemd5                enable MD5 passwords by default\n"
			 "     --enablenis                enable NIS\n"
			 "     --nisdomain <domain>       default NIS domain\n"
			 "     --nisserver <server>       default NIS server\n"

			 "     --enableldap               enable ldap for user information by default\n"
			 "     --enableldapauth           enable ldap for authentication by default\n"
			 "     --ldapserver <server>      default LDAP server\n"
			 "     --ldapbasedn <dn>          default LDAP base DN\n"

			 "     --enablekrb5               enable kerberos authentication by default\n"
			 "     --krb5kdc <server>         default kerberos KDC\n"
			 "     --krb5adminserver <server> default kerberos admin server\n"
			 "     --krb5realm <realm>        default kerberos realm\n"

			 "     --enablehesiod             enable hesiod for user information by default\n"
			 "     --hesiodlhs <lhs>          default hesiod LHS\n"
			 "     --hesiodrhs <rhs>          default hesiod RHS\n"

			 "     --kickstart                don't display user interface\n"
			 "     --help                     show this screen\n"),
	    progName);

    exit(0);
}

gboolean fileInaccessible(const char *path, int perms)
{
  struct stat st;
  if(stat(path, &st) == 0) {
    return (access(path, perms) == -1);
  } else {
    return (errno != ENOENT);
  }
}

int main(int argc, const char **argv)
{
  int rc;
  struct authInfoType *authInfo = NULL;
  gboolean nisAvail = FALSE, kerberosAvail = FALSE, ldapAvail = FALSE;

  int back = 0, test = 0, nostart = 0, kickstart = 0, help = 0;

  int useShadow = 0, enableMD5 = 0;

  int enableHesiod = 0;
  char *hesiodLHS = NULL, *hesiodRHS = NULL;

  int enableLDAP = 0, enableLDAPAuth = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;

  int enableNIS = 0;
  char *nisServer = NULL, *nisDomain = NULL;

  int enableKrb5 = 0;
  char *krb5Realm = NULL, *krb5KDC = NULL, *krb5AdminServer = NULL;

  poptContext optCon;
  const struct poptOption options[] = {
    { "back", '\0', POPT_ARG_NONE, &back, 0, NULL, NULL},
    { "test", '\0', POPT_ARG_NONE, &test, 0, NULL, NULL},
    { "nostart", '\0', POPT_ARG_NONE, &nostart, 0, NULL, NULL},
    { "kickstart", '\0', POPT_ARG_NONE, &kickstart, 0, NULL, NULL},

    { "useshadow", '\0', POPT_ARG_NONE, &useShadow, 0, NULL, NULL},
    { "enablemd5", '\0', POPT_ARG_NONE, &enableMD5, 0, NULL, NULL},

    { "enablehesiod", '\0', POPT_ARG_NONE, &enableHesiod, 0, NULL, NULL},
    { "hesiodlhs", '\0', POPT_ARG_STRING, &hesiodLHS, 0, NULL, NULL},
    { "hesiodrhs", '\0', POPT_ARG_STRING, &hesiodRHS, 0, NULL, NULL},

    { "enableldap", '\0', POPT_ARG_NONE, &enableLDAP, 0, NULL, NULL},
    { "enableldapauth", '\0', POPT_ARG_NONE, &enableLDAPAuth, 0, NULL, NULL},
    { "ldapserver", '\0', POPT_ARG_STRING, &ldapServer, 0, NULL, NULL},
    { "ldapbasedn", '\0', POPT_ARG_STRING, &ldapBaseDN, 0, NULL, NULL},

    { "enablekrb5", '\0', POPT_ARG_NONE, &enableKrb5, 0, NULL, NULL},
    { "krb5realm", '\0', POPT_ARG_STRING, &krb5Realm, 0, NULL, NULL},
    { "krb5kdc", '\0', POPT_ARG_STRING, &krb5KDC, 0, NULL, NULL},
    { "krb5adminserver", '\0', POPT_ARG_STRING, &krb5AdminServer, 0, NULL, NULL},

    { "enablenis", '\0', POPT_ARG_NONE, &enableNIS, 0, NULL, NULL},
    { "nisserver", '\0', POPT_ARG_STRING, &nisServer, 0, NULL, NULL},
    { "nisdomain", '\0', POPT_ARG_STRING, &nisDomain, 0, NULL, NULL},

    { "help", 'h', 0, &help, 0, NULL, NULL},
    { 0, 0, 0, 0, 0, 0 },
  };

  progName = basename((char*)argv[0]);

  /* first set up our locale info for gettext. */
  setlocale(LC_ALL, "");
  bindtextdomain("authconfig", "/usr/share/locale");
  textdomain("authconfig");
  
  /* next, process cmd. line options */
  optCon = poptGetContext("authconfig", argc, argv, options, 0);
  poptReadDefaultConfig(optCon, 1);
  
  if ((rc = poptGetNextOpt(optCon)) < -1) {
    fprintf(stderr, i18n("%s: bad argument %s: %s\n"),
	    progName, poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
	    poptStrerror(rc));
    return 2;
  }

  if (poptGetArg(optCon)) {
    fprintf(stderr, i18n("%s: unexpected argument\n"),
	    progName);
    return 2;
  }

  poptFreeContext(optCon);

  if (help)
      usage();
  
  /* if the test parameter wasn't passed, give an error if not root */
  if (!test && getuid()) {
    fprintf(stderr, i18n("%s: can only be run as root\n"),
	    progName);
    return 2;
  }

  /* allocate memory for the auth info structure */
  authInfo = g_malloc0(sizeof(struct authInfoType));

  /* read the values from the configuration files */
  if (authInfoReadHesiod(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/hesiod.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/hesiod.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadKerberos(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/krb5.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/krb5.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadLDAP(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/ldap.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/ldap.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadNIS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/yp.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/yp.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadNSS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/nsswitch.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/nsswitch.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadNetwork(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/sysconfig/network", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/sysconfig/network"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
  if (authInfoReadPAM(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/pam.d/%s"),
	      progName, SYSCONFDIR, AUTH_PAM_SERVICE);
      return 2;
    }
  }

  if ((access(PATH_YPBIND, X_OK) == 0) &&
      (access(PATH_LIBNSS_NIS, X_OK) == 0)) {
    nisAvail = TRUE;
  }
  if (access(PATH_PAM_KRB5, X_OK) == 0) {
    kerberosAvail = TRUE;
  }
  if ((access(PATH_PAM_LDAP, X_OK) == 0) &&
      (access(PATH_LIBNSS_LDAP, X_OK) == 0)) {
    ldapAvail = TRUE;
  }

  overrideBoolean(&authInfo->enableShadow, useShadow);
  overrideBoolean(&authInfo->enableMD5, enableMD5);

  overrideBoolean(&authInfo->enableHesiod, enableHesiod);
  overrideString(&authInfo->hesiodLHS, hesiodLHS);
  overrideString(&authInfo->hesiodRHS, hesiodRHS);

  overrideBoolean(&authInfo->enableLDAP, enableLDAP);
  overrideBoolean(&authInfo->enableLDAPAuth, enableLDAPAuth);
  overrideString(&authInfo->ldapServer, ldapServer);
  overrideString(&authInfo->ldapBaseDN, ldapBaseDN);

  overrideBoolean(&authInfo->enableNIS, enableNIS);
  overrideString(&authInfo->nisDomain, nisDomain);
  overrideString(&authInfo->nisServer, nisServer);

  overrideBoolean(&authInfo->enableKerberos, enableKrb5);
  overrideString(&authInfo->kerberosRealm, krb5Realm);
  overrideString(&authInfo->kerberosKDC, krb5KDC);
  overrideString(&authInfo->kerberosAdminServer, krb5AdminServer);

  if (!kickstart) {
    newtInit();
    newtCls();
    
    newtPushHelpLine(i18n(" <Tab>/<Alt-Tab> between elements   |   <Space> selects   |  <F12> next screen"));
    newtDrawRootText(0, 0, "authconfig " VERSION " - (c) 1999, 2000 Red Hat, Inc.");
    
    if (!getChoices(back, nisAvail, ldapAvail, kerberosAvail, authInfo)) {
      /* cancelled */
      newtFinished();
     
      if (test) {
	fprintf(stderr, i18n("dialog was cancelled\n"));
	return 2;
      }
      
      return 1;
    }
    
    newtFinished();
  } /* kickstart */

  if (test) {
    printf("nss_files is always enabled\n");
    printf("nss_hesiod is %s\n",
	   authInfo->enableHesiod ? "enabled" : "disabled");
    printf(" hesiod LHS = \"%s\"\n",
	   authInfo->hesiodLHS ? authInfo->hesiodLHS : "");
    printf(" hesiod RHS = \"%s\"\n",
	   authInfo->hesiodRHS ? authInfo->hesiodRHS : "");
    printf("nss_ldap is %s\n",
	   authInfo->enableLDAP ? "enabled" : "disabled");
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
    printf("pam_unix is always enabled\n");
    printf(" shadow passwords are %s\n",
	   authInfo->enableShadow ? "enabled" : "disabled");
    printf(" md5 passwords are %s\n",
	   authInfo->enableMD5 ? "enabled" : "disabled");
    printf("pam_krb5 is %s\n",
	   authInfo->enableKerberos ? "enabled" : "disabled");
    printf(" krb5 realm = \"%s\"\n",
	   authInfo->kerberosRealm ? authInfo->kerberosRealm : "");
    printf(" krb5 kdc = \"%s\"\n",
	   authInfo->kerberosKDC ? authInfo->kerberosKDC : "");
    printf(" krb5 admin server = \"%s\"\n",
	   authInfo->kerberosAdminServer ? authInfo->kerberosAdminServer : "");
    printf("pam_ldap is %s\n",
	   authInfo->enableLDAPAuth ? "enabled" : "disabled");
    printf(" LDAP server = \"%s\"\n",
	   authInfo->ldapServer ? authInfo->ldapServer : "");
    printf(" LDAP base DN = \"%s\"\n",
	   authInfo->ldapBaseDN ? authInfo->ldapBaseDN : "");
    return 0;
  } else {
    if (authInfoWriteHesiod(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/hesiod.conf", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/hesiod.conf"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWriteKerberos(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/krb5.conf", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/krb5.conf"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWriteLDAP(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/ldap.conf", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/ldap.conf"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWriteNIS(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/yp.conf", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/yp.conf"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWriteNSS(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/nsswitch.conf", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/nsswitch.conf"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWriteNetwork(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/sysconfig/network", R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/sysconfig/network"),
	        progName, SYSCONFDIR);
        return 2;
      }
    }
    if (authInfoWritePAM(authInfo) == FALSE) {
      if (fileInaccessible(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, R_OK)) {
        fprintf(stderr, i18n("%s: critical error writing %s/pam.d/%s"),
	        progName, SYSCONFDIR, AUTH_PAM_SERVICE);
        return 2;
      }
    }
  }

  return 0;
}
