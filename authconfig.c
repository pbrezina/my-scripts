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
	char nss_nis;
	newtComponent serverLabel, domainLabel;
	newtComponent serverEntry, domainEntry;
};
struct hesiod_cb {
	char nss_hesiod;
	newtComponent lhsLabel, rhsLabel;
	newtComponent lhsEntry, rhsEntry;
};
struct winBind_cb {
	char nss_winBind;
	char pam_winBind;
	newtComponent winBindDomainLabel;
	newtComponent winBindDomainEntry;
};
struct ldap_cb {
	char nss_ldap;
	char pam_ldap;
	newtComponent serverLabel, baseDnLabel;
       	newtComponent serverEntry, baseDnEntry;
};
struct krb5_cb {
	char pam_krb5;
	newtComponent krb5Checkbox;
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

void checkWarn(const char *path, const char *service, const char *package)
{
  char buf[LINE_MAX];

  if(access(path, R_OK) == 0) {
    return;
  }

  snprintf(buf, sizeof(buf), i18n("The %s file was not found, but it is "
           "required for %s support to work properly.  Install the %s package, "
           "which provides this file."), path, service, package);
 
  newtWinMessage(i18n("Warning"), i18n("Ok"), buf, NULL); 

  newtRefresh();
}

void nisToggle(newtComponent cb, void *data)
{
  struct nis_cb *nis = (struct nis_cb*) data;
  if(nis->nss_nis == '*') {
    checkWarn(PATH_YPBIND, "NIS", "ypbind");
    newtLabelSetText(nis->domainLabel, i18n("  Domain:"));
    newtLabelSetText(nis->serverLabel, i18n("  Server:"));
    newtEntrySetFlags(nis->domainEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(nis->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
    newtLabelSetText(nis->domainLabel, "");
    newtLabelSetText(nis->serverLabel, "");
    newtEntrySetFlags(nis->domainEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(nis->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
  }
  newtRefresh();
}

void hesiodToggle(newtComponent cb, void *data)
{
  struct hesiod_cb *hesiod = (struct hesiod_cb*) data;
  if(hesiod->nss_hesiod == '*') {
    newtLabelSetText(hesiod->lhsLabel, i18n("     LHS:"));
    newtLabelSetText(hesiod->rhsLabel, i18n("     RHS:"));
    newtEntrySetFlags(hesiod->lhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(hesiod->rhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
    newtLabelSetText(hesiod->lhsLabel, "");
    newtLabelSetText(hesiod->rhsLabel, "");
    newtEntrySetFlags(hesiod->lhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(hesiod->rhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
  }
  newtRefresh();
}

void ldapToggle(newtComponent cb, void *data)
{
  struct ldap_cb *ldap = (struct ldap_cb*) data;
  if((ldap->nss_ldap == '*') || (ldap->pam_ldap == '*')) {
    if(ldap->nss_ldap == '*') {
      checkWarn(PATH_LIBNSS_LDAP, "LDAP", "nss_ldap");
    } else {
      checkWarn(PATH_PAM_LDAP, "LDAP", "nss_ldap");
    }
    newtLabelSetText(ldap->serverLabel, i18n("  Server:"));
    newtLabelSetText(ldap->baseDnLabel, i18n(" Base DN:"));
    newtEntrySetFlags(ldap->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(ldap->baseDnEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
    newtLabelSetText(ldap->serverLabel, "");
    newtLabelSetText(ldap->baseDnLabel, "");
    newtEntrySetFlags(ldap->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(ldap->baseDnEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
  }
  newtRefresh();
}

#ifdef WINBIND
void winBindToggle(newtComponent cb, void *data)
{
  struct winBind_cb *winBind = (struct winBind_cb*) data;
  if((winBind->nss_winBind == '*') || (winBind->pam_winBind == '*')) {
    if(winBind->nss_winBind == '*') {
      checkWarn(PATH_LIBNSS_WINBIND, "WinBind", "winbind");
    } else {
      checkWarn(PATH_PAM_WINBIND, "WinBind", "winbind");
    }
    newtLabelSetText(winBind->winBindDomainLabel, i18n("  Domain:"));
    newtEntrySetFlags(winBind->winBindDomainEntry,
		      NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN, NEWT_FLAGS_RESET);
  } else {
    newtLabelSetText(winBind->winBindDomainLabel, "");
    newtEntrySetFlags(winBind->winBindDomainEntry,
		      NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN, NEWT_FLAGS_SET);
  }
  newtRefresh();
}
#endif

void krb5Toggle(newtComponent cb, void *data)
{
  struct krb5_cb *krb5 = (struct krb5_cb*) data;
  if(krb5->pam_krb5 == '*') {
    checkWarn(PATH_PAM_KRB5, "Kerberos", "pam_krb5");
    newtLabelSetText(krb5->realmLabel,  i18n("          Realm:"));
    newtLabelSetText(krb5->kdcLabel,    i18n("            KDC:"));
    newtLabelSetText(krb5->kadminLabel, i18n("   Admin Server:"));
    newtEntrySetFlags(krb5->realmEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(krb5->kdcEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(krb5->kadminEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
    newtLabelSetText(krb5->realmLabel, "");
    newtLabelSetText(krb5->kdcLabel, "");
    newtLabelSetText(krb5->kadminLabel, "");
    newtEntrySetFlags(krb5->realmEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(krb5->kdcEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(krb5->kadminEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
  }
  newtRefresh();
}

int getNSSChoices(int back,
	          gboolean nisAvail, gboolean ldapAvail,
		  gboolean kerberosAvail, gboolean winBindAvail,
	          struct authInfoType *authInfo)
{
  newtComponent form, ok, cancel, comp, cb;
  int rc = 0;

  struct nis_cb nis;
  struct hesiod_cb hesiod;
  struct winBind_cb winBind;
  struct ldap_cb ldap;

  char *hesiodLHS = NULL, *hesiodRHS = NULL;
  char *ldapServer = NULL, *ldapBaseDN = NULL;
  char *nisServer = NULL, *nisDomain = NULL;
  char *winBindDomain = NULL;

  /* Create the window and a form to put into it. */
  newtCenteredWindow(62, 14, i18n("User Information Configuration"));
  form = newtForm(NULL, NULL, 0);

  /* NSS modules: NIS. */
  cb = newtCheckbox(1, 1, i18n("Use NIS"), authInfo->enableNIS ? '*' : ' ',
		    NULL, &nis.nss_nis);
  nis.domainLabel = newtLabel(16, 1, "");
  nis.domainEntry = newtEntry(26, 1, authInfo->nisDomain, 35, &nisDomain,
		  	      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(nis.domainEntry, entryFilter, NULL);
  nis.serverLabel = newtLabel(16, 2, "");
  nis.serverEntry = newtEntry(26, 2, authInfo->nisServer, 35, &nisServer,
		  	      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(nis.serverEntry, entryFilter, NULL);
  newtFormAddComponents(form,
		  	cb,
			nis.domainLabel,
			nis.domainEntry,
			nis.serverLabel,
			nis.serverEntry,
			NULL);
  newtComponentAddCallback(cb, nisToggle, &nis);

  /* Make this checkbox the starting location. */
  newtFormSetCurrent(form, cb);

  ldap.pam_ldap = authInfo->enableLDAPAuth ? '*' : ' ';
  cb = newtCheckbox(1, 4, i18n("Use LDAP"),
		    authInfo->enableLDAP ? '*' : ' ', NULL, &ldap.nss_ldap);
  ldap.serverLabel = newtLabel(16, 4, "");
  ldap.serverEntry = newtEntry(26, 4, authInfo->ldapServer, 35, &ldapServer,
		  	       NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(ldap.serverEntry, entryFilter, NULL);
  ldap.baseDnLabel = newtLabel(16, 5, "");
  ldap.baseDnEntry = newtEntry(26, 5, authInfo->ldapBaseDN, 35, &ldapBaseDN,
		  	       NEWT_ENTRY_SCROLL);
  newtFormAddComponents(form,
		  	cb,
		  	ldap.serverLabel,
			ldap.baseDnLabel,
			ldap.serverEntry,
			ldap.baseDnEntry,
			NULL);
  newtComponentAddCallback(cb, ldapToggle, &ldap);

#ifdef WINBIND
  cb = newtCheckbox(1, 7, i18n("Use WinBind"),
		    authInfo->enableWinBind ? '*' : ' ', NULL,
		    &winBind.nss_winBind);
  winBind.winBindDomainLabel = newtLabel(16, 7, "");
  winBind.winBindDomainEntry = newtEntry(26, 7, authInfo->winBindDomain, 35,
		 			 &winBindDomain, NEWT_ENTRY_SCROLL);
  newtFormAddComponents(form,
		  	cb,
			winBind.winBindDomainLabel,
			winBind.winBindDomainEntry,
			NULL);
  newtComponentAddCallback(cb, winBindToggle, &winBind);
#endif

  cb = newtCheckbox(1, 7, i18n("Use Hesiod"),
		    authInfo->enableHesiod ? '*' : ' ', NULL,
		    &hesiod.nss_hesiod);
  hesiod.lhsLabel = newtLabel(16, 7, "");
  hesiod.lhsEntry = newtEntry(26, 7, authInfo->hesiodLHS, 35, &hesiodLHS,
			      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(hesiod.lhsEntry, entryFilter, NULL);
  hesiod.rhsLabel = newtLabel(16,  8, "");
  hesiod.rhsEntry = newtEntry(26,  8, authInfo->hesiodRHS, 35, &hesiodRHS,
			      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(hesiod.lhsEntry, entryFilter, NULL);
  newtFormAddComponents(form,
		  	cb,
			hesiod.lhsLabel,
			hesiod.lhsEntry,
			hesiod.rhsLabel,
			hesiod.rhsEntry,
			NULL);
  newtComponentAddCallback(cb, hesiodToggle, &hesiod);

  /* Create the buttons. */
  ok = newtButton(16, 10, i18n("Next"));
  cancel = newtButton(35, 10, back ? i18n("Back") : i18n("Cancel"));
  newtFormAddComponents(form, ok, cancel, NULL);

  /* Call all of the callbacks to initialize disabled fields. */
  nisToggle(NULL, &nis);
  ldapToggle(NULL, &ldap);
  hesiodToggle(NULL, &hesiod);
#ifdef WINBIND
  winBindToggle(NULL, &winBind);
#endif

  /* Run the form and interpret the results. */
  comp = newtRunForm(form);
  if(comp != cancel) {
    authInfo->enableHesiod = (hesiod.nss_hesiod == '*');
    setString(&authInfo->hesiodLHS, hesiodLHS);
    setString(&authInfo->hesiodRHS, hesiodRHS);

    authInfo->enableLDAP = (ldap.nss_ldap == '*');
    setString(&authInfo->ldapServer, ldapServer);
    setString(&authInfo->ldapBaseDN, ldapBaseDN);

    authInfo->enableNIS = (nis.nss_nis == '*');
    setString(&authInfo->nisServer, nisServer);
    setString(&authInfo->nisDomain, nisDomain);

#ifdef WINBIND
    authInfo->enableWinBind = (winBind.nss_winBind == '*');
    setString(&authInfo->winBindDomain, winBindDomain);
#endif

    rc = 1;
  }
  if(comp == cancel) {
    rc = 0;
  }
  newtFormDestroy(form);
  newtPopWindow();

  return rc;
}

int getPAMChoices(int back,
	          gboolean nisAvail, gboolean ldapAvail,
		  gboolean kerberosAvail, gboolean winBindAvail,
	          struct authInfoType *authInfo)
{
  newtComponent form, ok, backb = NULL, cancel = NULL, comp, cb;
  int rc = 0;

  struct ldap_cb ldap;
  struct krb5_cb krb5;
  struct winBind_cb winBind;

  char shadow = 0, md5 = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;
  char *kerberosRealm = NULL, *kerberosKDC = NULL, *kerberosAdmin = NULL;
  char *winBindDomain = NULL;

  /* Create the window and a form to put into it. */
  newtCenteredWindow(72, 16, i18n("Authentication Configuration"));
  form = newtForm(NULL, NULL, 0);

  /* PAM setup. */
  cb = newtCheckbox(1, 1, i18n("Use Shadow Passwords"),
		    authInfo->enableShadow ? '*' : ' ', NULL, &shadow);
  newtFormAddComponent(form, cb);

  cb = newtCheckbox(1, 3, i18n("Use MD5 Passwords"),
		    authInfo->enableMD5 ? '*' : ' ', NULL, &md5);
  newtFormAddComponent(form, cb);

  ldap.nss_ldap = authInfo->enableLDAP ? '*' : ' ';
  cb = newtCheckbox(1, 5, i18n("Use LDAP Authentication"),
		    authInfo->enableLDAPAuth ? '*' : ' ', NULL, &ldap.pam_ldap);

  newtComponentAddCallback(cb, ldapToggle, &ldap);
  ldap.serverLabel = newtLabel(31, 5, "");
  ldap.serverEntry = newtEntry(41, 5, authInfo->ldapServer, 30, &ldapServer,
		  	       NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(ldap.serverEntry, entryFilter, NULL);
  ldap.baseDnLabel = newtLabel(31, 6, "");
  ldap.baseDnEntry = newtEntry(41, 6, authInfo->ldapBaseDN, 30, &ldapBaseDN,
		  	       NEWT_ENTRY_SCROLL);
  newtFormAddComponents(form,
		  	cb,
		  	ldap.serverLabel,
			ldap.baseDnLabel,
			ldap.serverEntry,
			ldap.baseDnEntry,
			NULL);
  newtComponentAddCallback(cb, ldapToggle, &ldap);
#ifdef WINBIND
  winBind.pam_winBind = authInfo->enableWinBindAuth ? '*' : ' ';
  cb = newtCheckbox(1, 8, i18n("Use WinBind Authentication"),
		    authInfo->enableWinBindAuth ? '*' : ' ',
		    NULL, &winBind.pam_winBind);
  newtComponentAddCallback(cb, winBindToggle, &winBind);

  winBind.winBindDomainLabel = newtLabel(31, 8, "");
  winBind.winBindDomainEntry = newtEntry(41, 8, authInfo->winBindDomain, 30,
					 &winBindDomain, NEWT_ENTRY_SCROLL);
  newtFormAddComponents(form,
		  	cb,
		  	winBind.winBindDomainLabel,
			winBind.winBindDomainEntry,
			NULL);
  newtComponentAddCallback(cb, winBindToggle, &winBind);
#endif
  cb = newtCheckbox(1,  8, i18n("Use Kerberos 5"),
		    authInfo->enableKerberos ? '*' : ' ', NULL, &krb5.pam_krb5);
  krb5.realmLabel = newtLabel(24,  8, "");
  krb5.realmEntry = newtEntry(41,  8, authInfo->kerberosRealm, 30,
		  	      &kerberosRealm, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.realmEntry, entryFilter, NULL);
  krb5.kdcLabel = newtLabel(24,  9, "");
  krb5.kdcEntry = newtEntry(41,  9, authInfo->kerberosKDC, 30,
		  	    &kerberosKDC, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.kdcEntry, entryFilter, NULL);
  krb5.kadminLabel = newtLabel(24, 10, "");
  krb5.kadminEntry = newtEntry(41, 10, authInfo->kerberosAdminServer, 30,
		  	       &kerberosAdmin, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.kadminEntry, entryFilter, NULL);
  newtComponentAddCallback(cb, krb5Toggle, &krb5);
  newtFormAddComponents(form,
		  	cb,
			krb5.realmLabel,
			krb5.realmEntry,
			krb5.kdcLabel,
			krb5.kdcEntry,
			krb5.kadminLabel,
			krb5.kadminEntry,
			NULL);

  /* Create the buttons. */
  if (back == FALSE) {
    ok = newtButton(14, 12, i18n("Ok"));
    backb = newtButton(44, 12, i18n("Back"));
    cancel = newtButton(27, 12, i18n("Cancel"));
    newtFormAddComponents(form, ok, cancel, backb, NULL);
  } else {
    ok = newtButton(20, 12, i18n("Ok"));
    backb = newtButton(38, 12, i18n("Back"));
    newtFormAddComponents(form, ok, backb, NULL);
  }

  /* Call all of the callbacks to initialize disabled fields. */
  ldapToggle(NULL, &ldap);
  krb5Toggle(NULL, &krb5);
#ifdef WINBIND
  winBindToggle(NULL, &winBind);
#endif

  /* Run the form and interpret the results. */
  comp = newtRunForm(form);
  if((comp != cancel) && (comp != backb)) {
    authInfo->enableMD5 = (md5 == '*');
    authInfo->enableShadow = (shadow == '*');

    authInfo->enableLDAPAuth = (ldap.pam_ldap == '*');
    setString(&authInfo->ldapServer, ldapServer);
    setString(&authInfo->ldapBaseDN, ldapBaseDN);
#ifdef WINBIND
    authInfo->enableWinBindAuth = (winBind.pam_winBind == '*');
    setString(&authInfo->winBindDomain, winBindDomain);
#endif
    authInfo->enableKerberos = (krb5.pam_krb5 == '*');
    setString(&authInfo->kerberosRealm, kerberosRealm);
    setString(&authInfo->kerberosKDC, kerberosKDC);
    setString(&authInfo->kerberosAdminServer, kerberosAdmin);

    rc = 1;
  }
  if(comp == cancel) {
    rc = 0;
  }
  if(comp == backb) {
    rc = 2;
  }
  newtFormDestroy(form);
  newtPopWindow();

  return rc;
}

int getChoices(int back,
	       gboolean nisAvail, gboolean ldapAvail,
	       gboolean kerberosAvail, gboolean winBindAvail,
	       struct authInfoType *authInfo)
{
  int rc = FALSE, next = 1, i;

  /* State machine (couldn't come up with a cleaner way to express the logic):
   * 1: query for NSS setup.
   * 2: query for PAM setup.
   * 0: quit */
  while (next != 0) {
    switch (next) {
      case 1:
	i = getNSSChoices(back, nisAvail, ldapAvail, kerberosAvail, winBindAvail, authInfo);
        switch(i) {
          case 1:
	    next = 2;
	    break;
          case 0:
	    next = 0;
	    break;
	}
	break;
      case 2:
	i = getPAMChoices(back, nisAvail, ldapAvail, kerberosAvail, winBindAvail, authInfo);
        switch(i) {
          case 2:
	    next = 1;
	    break;
          case 1:
	    next = 0;
	    rc = TRUE;
	    break;
          case 0:
	    next = 0;
	    break;
	}
    }
  }

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
  gboolean nisAvail = FALSE, kerberosAvail = FALSE;
  gboolean ldapAvail = FALSE, winBindAvail = FALSE;

  int back = 0, test = 0, nostart = 0, kickstart = 0, help = 0;

  int useShadow = 0, enableMD5 = 0;

  int enableHesiod = 0;
  char *hesiodLHS = NULL, *hesiodRHS = NULL;

  int enableLDAP = 0, enableLDAPAuth = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;

  int enableWinBind = 0, enableWinBindAuth = 0;
  char *winBindDomain = NULL;

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
#ifdef WINBIND
    { "enablewinbind", '\0', POPT_ARG_NONE, &enableWinBind, 0, NULL, NULL},
    { "enablewinbindauth", '\0', POPT_ARG_NONE, &enableWinBindAuth, 0, NULL, NULL},
    { "winbinddomain", '\0', POPT_ARG_STRING, &winBindDomain, 0, NULL, NULL},
#endif

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
#ifdef WINBIND
  if (authInfoReadWinBind(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/smb.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/smb.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
  }
#endif
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
  if ((access(PATH_PAM_WINBIND, X_OK) == 0) &&
      (access(PATH_LIBNSS_WINBIND, X_OK) == 0)) {
    winBindAvail = TRUE;
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

#ifdef WINBIND
  overrideBoolean(&authInfo->enableWinBind, enableWinBind);
  overrideBoolean(&authInfo->enableWinBindAuth, enableWinBindAuth);
  overrideString(&authInfo->winBindDomain, winBindDomain);
#endif

  if (!kickstart) {
    newtInit();
    newtCls();
    
    newtPushHelpLine(i18n(" <Tab>/<Alt-Tab> between elements   |   <Space> selects   |  <F12> next screen"));
    newtDrawRootText(0, 0, "authconfig " VERSION " - (c) 1999, 2000 Red Hat, Inc.");
    
    if (!getChoices(back, nisAvail, ldapAvail, kerberosAvail, winBindAvail, authInfo)) {
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
#ifdef WINBIND
    printf("nss_winbind is %s\n",
	   authInfo->enableWinBind ? "enabled" : "disabled");
    printf(" winbind domain = \"%s\"\n",
	   authInfo->winBindDomain ? authInfo->winBindDomain : "");
#endif
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
#ifdef WINBIND
    printf("pam_winbind is %s\n",
	   authInfo->enableWinBindAuth ? "enabled" : "disabled");
    printf(" winbind domain = \"%s\"\n",
	   authInfo->winBindDomain ? authInfo->winBindDomain : "");
#endif
    return 0;
  } else {
    if (authInfoWriteHesiod(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/hesiod.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
    if (authInfoWriteKerberos(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/krb5.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
    if (authInfoWriteLDAP(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/ldap.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
    if (authInfoWriteNIS(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/yp.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
#ifdef WINBIND
    if (authInfoWriteWinBind(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/smb.conf"),
	      progName, SYSCONFDIR);
      return 2;
    }
#endif
    if (authInfoWriteNSS(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/nsswitch.conf"),
	      progName, SYSCONFDIR);
    }
    if (authInfoWriteNetwork(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/sysconfig/network"),
	      progName, SYSCONFDIR);
      return 2;
    }
    if (authInfoWritePAM(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/pam.d/%s"),
	      progName, SYSCONFDIR, AUTH_PAM_SERVICE);
      return 2;
    }
    toggleShadow(authInfo);
    toggleNisService(authInfo->enableNIS, authInfo->nisDomain, nostart);
  }

  return 0;
}
