/*
 * Authconfig - authentication configuration program
 * Author: Nalin Dahyabhai <nalin@redhat.com>
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
#ifdef LOCAL_POLICIES
#include "localpol.h"
#endif

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
  struct stat st;

  if (enableNis && (nisDomain != NULL) && (strlen(nisDomain) > 0)) { 
    domainStr = g_strdup_printf("/bin/domainname %s", nisDomain);
    system(domainStr);
    g_free(domainStr);
    if(stat(PATH_PORTMAP, &st) == 0) {
      system("/sbin/chkconfig --add portmap");
      system("/sbin/chkconfig --level 345 portmap on");
      if (!nostart) {
        system("/sbin/service portmap restart");
      }
    }
    if(stat(PATH_YPBIND, &st) == 0) {
      system("/sbin/chkconfig --add ypbind");
      system("/sbin/chkconfig --level 345 ypbind on");
      if (!nostart) {
        if(stat(PATH_YPBIND_PID, &st) == 0) {
          system("/sbin/service ypbind restart");
	} else {
          system("/sbin/service ypbind start");
	}
      }
    }
  } else {
    system("/bin/domainname \"(none)\"");
    if(stat(PATH_YPBIND, &st) == 0) {
      if (!nostart) {
        if(stat(PATH_YPBIND_PID, &st) == 0) {
          system("/sbin/service ypbind stop");
	}
      }
      system("/sbin/chkconfig --del ypbind");
    }
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

void overrideBoolean(gboolean *dest, int switch_on, int switch_off)
{
  if (switch_on) *dest = TRUE;
  if (switch_off) *dest = FALSE;
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
  newtLabelSetText(nis->domainLabel, i18n("  Domain:"));
  newtLabelSetText(nis->serverLabel, i18n("  Server:"));
  if(nis->nss_nis == '*') {
    checkWarn(PATH_YPBIND, "NIS", "ypbind");
    newtEntrySetFlags(nis->domainEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(nis->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
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
  newtLabelSetText(hesiod->lhsLabel, i18n("     LHS:"));
  newtLabelSetText(hesiod->rhsLabel, i18n("     RHS:"));
  if(hesiod->nss_hesiod == '*') {
    newtEntrySetFlags(hesiod->lhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(hesiod->rhsEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
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
  newtLabelSetText(ldap->serverLabel, i18n("  Server:"));
  newtLabelSetText(ldap->baseDnLabel, i18n(" Base DN:"));
  if((ldap->nss_ldap == '*') || (ldap->pam_ldap == '*')) {
    if(ldap->nss_ldap == '*') {
      checkWarn(PATH_LIBNSS_LDAP, "LDAP", "nss_ldap");
    } else {
      checkWarn(PATH_PAM_LDAP, "LDAP", "nss_ldap");
    }
    newtEntrySetFlags(ldap->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(ldap->baseDnEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
    newtEntrySetFlags(ldap->serverEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
    newtEntrySetFlags(ldap->baseDnEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_SET);
  }
  newtRefresh();
}

void krb5Toggle(newtComponent cb, void *data)
{
  struct krb5_cb *krb5 = (struct krb5_cb*) data;
  newtLabelSetText(krb5->realmLabel,  i18n("          Realm:"));
  newtLabelSetText(krb5->kdcLabel,    i18n("            KDC:"));
  newtLabelSetText(krb5->kadminLabel, i18n("   Admin Server:"));
  if(krb5->pam_krb5 == '*') {
    checkWarn(PATH_PAM_KRB5, "Kerberos", "pam_krb5");
    newtEntrySetFlags(krb5->realmEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(krb5->kdcEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
    newtEntrySetFlags(krb5->kadminEntry, NEWT_FLAG_DISABLED | NEWT_FLAG_HIDDEN,
		      NEWT_FLAGS_RESET);
  } else {
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
		  gboolean kerberosAvail, struct authInfoType *authInfo)
{
  newtComponent form, ok, cancel, comp, cb;
  newtGrid mainGrid, mechGrid, buttonGrid;
  int rc = 0;

  struct nis_cb nis;
  struct hesiod_cb hesiod;
  struct ldap_cb ldap;

  char *hesiodLHS = NULL, *hesiodRHS = NULL;
  char *ldapServer = NULL, *ldapBaseDN = NULL;
  char *nisServer = NULL, *nisDomain = NULL;

  mechGrid = newtCreateGrid(3, 6);

  /* NSS modules: NIS. */
  cb = newtCheckbox(-1, -1, i18n("Use NIS"), authInfo->enableNIS ? '*' : ' ',
		    NULL, &nis.nss_nis);
  newtComponentAddCallback(cb, nisToggle, &nis);

  nis.domainLabel = newtLabel(-1, -1, "");
  nis.domainEntry = newtEntry(-1, -1, authInfo->nisDomain, 35, &nisDomain,
		  	      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(nis.domainEntry, entryFilter, NULL);

  nis.serverLabel = newtLabel(-1, -1, "");
  nis.serverEntry = newtEntry(-1, -1, authInfo->nisServer, 35, &nisServer,
		  	      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(nis.serverEntry, entryFilter, NULL);

  newtGridSetField(mechGrid, 0, 0, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 0, NEWT_GRID_COMPONENT, nis.domainLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 0, NEWT_GRID_COMPONENT, nis.domainEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 1, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 1, NEWT_GRID_COMPONENT, nis.serverLabel,
		   0, 0, 0, 1, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 1, NEWT_GRID_COMPONENT, nis.serverEntry,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  /* NSS modules: LDAP. */
  ldap.pam_ldap = authInfo->enableLDAPAuth ? '*' : ' ';
  cb = newtCheckbox(-1, -1, i18n("Use LDAP"),
		    authInfo->enableLDAP ? '*' : ' ', NULL, &ldap.nss_ldap);
  newtComponentAddCallback(cb, ldapToggle, &ldap);

  ldap.serverLabel = newtLabel(-1, -1, "");
  ldap.serverEntry = newtEntry(-1, -1, authInfo->ldapServer, 35, &ldapServer,
		  	       NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(ldap.serverEntry, entryFilter, NULL);

  ldap.baseDnLabel = newtLabel(-1, -1, "");
  ldap.baseDnEntry = newtEntry(-1, -1, authInfo->ldapBaseDN, 35, &ldapBaseDN,
		  	       NEWT_ENTRY_SCROLL);

  newtGridSetField(mechGrid, 0, 2, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 2, NEWT_GRID_COMPONENT, ldap.serverLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 2, NEWT_GRID_COMPONENT, ldap.serverEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 3, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 3, NEWT_GRID_COMPONENT, ldap.baseDnLabel,
		   0, 0, 0, 1, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 3, NEWT_GRID_COMPONENT, ldap.baseDnEntry,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  /* NSS modules: LDAP. */
  cb = newtCheckbox(-1, -1, i18n("Use Hesiod"),
		    authInfo->enableHesiod ? '*' : ' ', NULL,
		    &hesiod.nss_hesiod);
  newtComponentAddCallback(cb, hesiodToggle, &hesiod);

  hesiod.lhsLabel = newtLabel(-1, -1, "");
  hesiod.lhsEntry = newtEntry(-1, -1, authInfo->hesiodLHS, 35, &hesiodLHS,
			      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(hesiod.lhsEntry, entryFilter, NULL);

  hesiod.rhsLabel = newtLabel(-1, -1, "");
  hesiod.rhsEntry = newtEntry(-1, -1, authInfo->hesiodRHS, 35, &hesiodRHS,
			      NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(hesiod.lhsEntry, entryFilter, NULL);

  newtGridSetField(mechGrid, 0, 4, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 4, NEWT_GRID_COMPONENT, hesiod.lhsLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 4, NEWT_GRID_COMPONENT, hesiod.lhsEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 5, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 5, NEWT_GRID_COMPONENT, hesiod.rhsLabel,
		   0, 0, 0, 1, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 5, NEWT_GRID_COMPONENT, hesiod.rhsEntry,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  /* Create the buttons. */
  buttonGrid = newtCreateGrid(2, 1);
  ok = newtButton(-1, -1, i18n("Next"));
  cancel = newtButton(-1, -1, back ? i18n("Back") : i18n("Cancel"));
  newtGridSetField(buttonGrid, 0, 0, NEWT_GRID_COMPONENT, ok,
		   0, 0, 0, 0, 0, 0);
  newtGridSetField(buttonGrid, 1, 0, NEWT_GRID_COMPONENT, cancel,
		   0, 0, 0, 0, 0, 0);

  /* Call all of the callbacks to initialize disabled fields. */
  nisToggle(NULL, &nis);
  ldapToggle(NULL, &ldap);
  hesiodToggle(NULL, &hesiod);

  /* Finish generating the form. */
  mainGrid = newtCreateGrid(1, 2);
  newtGridSetField(mainGrid, 0, 0, NEWT_GRID_SUBGRID, mechGrid,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, buttonGrid,
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);

  form = newtForm(NULL, NULL, 0);
  newtGridWrappedWindow(mainGrid, i18n("User Information Configuration"));
  newtGridAddComponentsToForm(mainGrid, form, 1);

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
		  gboolean kerberosAvail, struct authInfoType *authInfo)
{
  newtComponent form, ok, backb = NULL, cancel = NULL, comp, cb;
  newtGrid mainGrid, mechGrid, buttonGrid;
  int rc = 0;

  struct ldap_cb ldap;
  struct krb5_cb krb5;

  char shadow = 0, md5 = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;
  char *kerberosRealm = NULL, *kerberosKDC = NULL, *kerberosAdmin = NULL;

#ifdef LOCAL_POLICIES
  char local = ' ';
#endif

  /* Create the window and a form to put into it. */
  mainGrid = newtCreateGrid(1, 2);

  /* PAM setup. */
  mechGrid = newtCreateGrid(3, 8);
  cb = newtCheckbox(-1, -1, i18n("Use Shadow Passwords"),
		    authInfo->enableShadow ? '*' : ' ', NULL, &shadow);
  newtGridSetField(mechGrid, 0, 0, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);

  cb = newtCheckbox(-1, -1, i18n("Use MD5 Passwords"),
		    authInfo->enableMD5 ? '*' : ' ', NULL, &md5);
  newtGridSetField(mechGrid, 0, 1, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);

  ldap.nss_ldap = authInfo->enableLDAP ? '*' : ' ';
  cb = newtCheckbox(-1, -1, i18n("Use LDAP Authentication"),
		    authInfo->enableLDAPAuth ? '*' : ' ', NULL, &ldap.pam_ldap);
  newtComponentAddCallback(cb, ldapToggle, &ldap);

  ldap.serverLabel = newtLabel(-1, -1, "");
  ldap.serverEntry = newtEntry(-1, -1, authInfo->ldapServer, 30, &ldapServer,
		  	       NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(ldap.serverEntry, entryFilter, NULL);

  ldap.baseDnLabel = newtLabel(-1, -1, "");
  ldap.baseDnEntry = newtEntry(-1, -1, authInfo->ldapBaseDN, 30, &ldapBaseDN,
		  	       NEWT_ENTRY_SCROLL);

  newtGridSetField(mechGrid, 0, 2, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 2, NEWT_GRID_COMPONENT, ldap.serverLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 2, NEWT_GRID_COMPONENT, ldap.serverEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 3, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 3, NEWT_GRID_COMPONENT, ldap.baseDnLabel,
		   0, 0, 0, 1, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 3, NEWT_GRID_COMPONENT, ldap.baseDnEntry,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  cb = newtCheckbox(-1, -1, i18n("Use Kerberos 5"),
		    authInfo->enableKerberos ? '*' : ' ', NULL, &krb5.pam_krb5);
  newtComponentAddCallback(cb, krb5Toggle, &krb5);

  krb5.realmLabel = newtLabel(-1, -1, "");
  krb5.realmEntry = newtEntry(-1, -1, authInfo->kerberosRealm, 30,
		  	      &kerberosRealm, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.realmEntry, entryFilter, NULL);

  krb5.kdcLabel = newtLabel(-1, -1, "");
  krb5.kdcEntry = newtEntry(-1, -1, authInfo->kerberosKDC, 30,
		  	    &kerberosKDC, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.kdcEntry, entryFilter, NULL);

  krb5.kadminLabel = newtLabel(-1, -1, "");
  krb5.kadminEntry = newtEntry(-1, -1, authInfo->kerberosAdminServer, 30,
		  	       &kerberosAdmin, NEWT_ENTRY_SCROLL);
  newtEntrySetFilter(krb5.kadminEntry, entryFilter, NULL);

  newtGridSetField(mechGrid, 0, 4, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 4, NEWT_GRID_COMPONENT, krb5.realmLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 4, NEWT_GRID_COMPONENT, krb5.realmEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 5, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 5, NEWT_GRID_COMPONENT, krb5.kdcLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 5, NEWT_GRID_COMPONENT, krb5.kdcEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mechGrid, 0, 6, NEWT_GRID_COMPONENT, newtLabel(-1, -1, ""),
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 6, NEWT_GRID_COMPONENT, krb5.kadminLabel,
		   0, 0, 0, 1, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(mechGrid, 2, 6, NEWT_GRID_COMPONENT, krb5.kadminEntry,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

#ifdef LOCAL_POLICIES
  cb = newtCheckbox(1,  12, LOCAL_POLICY_COMMENT,
		    authInfo->enableLocal ? '*' : ' ', NULL, &local);
  newtGridSetField(mechGrid, 0, 7, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
#endif

  newtGridSetField(mainGrid, 0, 0, NEWT_GRID_SUBGRID, mechGrid,
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);

  /* Create the buttons. */
  if (back == FALSE) {
    ok = newtButton(-1, -1, i18n("Ok"));
    backb = newtButton(-1, -1, i18n("Back"));
    cancel = newtButton(-1, -1, i18n("Cancel"));
    buttonGrid = newtCreateGrid(3, 1);
    newtGridSetField(buttonGrid, 0, 0, NEWT_GRID_COMPONENT, ok,
		     0, 0, 0, 0, 0, 0);
    newtGridSetField(buttonGrid, 1, 0, NEWT_GRID_COMPONENT, backb,
		     0, 0, 0, 0, 0, 0);
    newtGridSetField(buttonGrid, 2, 0, NEWT_GRID_COMPONENT, cancel,
		     0, 0, 0, 0, 0, 0);
    newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, buttonGrid,
		     0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);
  } else {
    ok = newtButton(-1, -1, i18n("Ok"));
    backb = newtButton(-1, -1, i18n("Back"));
    buttonGrid = newtCreateGrid(2, 1);
    newtGridSetField(buttonGrid, 0, 0, NEWT_GRID_COMPONENT, ok,
		     0, 0, 0, 0, 0, 0);
    newtGridSetField(buttonGrid, 1, 0, NEWT_GRID_COMPONENT, backb,
		     0, 0, 0, 0, 0, 0);
    newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, buttonGrid,
		     0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);
  }

  /* Call all of the callbacks to initialize disabled fields. */
  ldapToggle(NULL, &ldap);
  krb5Toggle(NULL, &krb5);

  /* Run the form and interpret the results. */
  form = newtForm(NULL, NULL, 0);
  newtGridWrappedWindow(mainGrid, i18n("Authentication Configuration"));
  newtGridAddComponentsToForm(mainGrid, form, 1);
  comp = newtRunForm(form);
  if((comp != cancel) && (comp != backb)) {
    authInfo->enableMD5 = (md5 == '*');
    authInfo->enableShadow = (shadow == '*');

    authInfo->enableLDAPAuth = (ldap.pam_ldap == '*');
    setString(&authInfo->ldapServer, ldapServer);
    setString(&authInfo->ldapBaseDN, ldapBaseDN);
    authInfo->enableKerberos = (krb5.pam_krb5 == '*');
#ifdef LOCAL_POLICIES
    authInfo->enableLocal = (local == '*');
#endif
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
	       gboolean kerberosAvail, struct authInfoType *authInfo)
{
  int rc = FALSE, next = 1, i;

  /* State machine (couldn't come up with a cleaner way to express the logic):
   * 1: query for NSS setup.
   * 2: query for PAM setup.
   * 0: quit */
  while (next != 0) {
    switch (next) {
      case 1:
	i = getNSSChoices(back, nisAvail, ldapAvail, kerberosAvail, authInfo);
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
	i = getPAMChoices(back, nisAvail, ldapAvail, kerberosAvail, authInfo);
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
    fprintf(stderr, gettext("Usage: %s [options]\n\n"
			    "     --useshadow\n"
			    "     --enableshadow             enable shadow passwords by default\n"
			    "     --disableshadow            disable shadow passwords by default\n"
			    "     --enablemd5                enable MD5 passwords by default\n"
			    "     --disablemd5               disable MD5 passwords by default\n"
			    "\n"
			    "     --enablenis                enable NIS\n"
			    "     --disablenis               disable NIS\n"
			    "     --nisdomain <domain>       default NIS domain\n"
			    "     --nisserver <server>       default NIS server\n"
			    "\n"
   
			    "     --enableldap               enable ldap for user information by default\n"
			    "     --disableldap              disable ldap for user information by default\n"
			    "     --enableldapauth           enable ldap for authentication by default\n"
			    "     --disableldapauth          disable ldap for authentication by default\n"
			    "     --ldapserver <server>      default LDAP server\n"
			    "     --ldapbasedn <dn>          default LDAP base DN\n"
			    "\n"

			    "     --enablekrb5               enable kerberos authentication by default\n"
			    "     --disablekrb5              disable kerberos authentication by default\n"
			    "     --krb5kdc <server>         default kerberos KDC\n"
			    "     --krb5adminserver <server> default kerberos admin server\n"
			    "     --krb5realm <realm>        default kerberos realm\n"
			    "\n"
   
			    "     --enablehesiod             enable hesiod for user information by default\n"
			    "     --disablehesiod            disable hesiod for user information by default\n"
			    "     --hesiodlhs <lhs>          default hesiod LHS\n"
			    "     --hesiodrhs <rhs>          default hesiod RHS\n"
			    "\n"

			    "     --nostart                  do not start/stop ypbind\n"
			    "     --kickstart                don't display user interface\n"
			    "     --help                     show this screen\n"),
	    progName);
#ifdef LOCAL_POLICIES
    fprintf(stderr, gettext("\n"
			    "     --enablelocal              use locally-defined policy " LOCAL_POLICY_NAME "\n"
			    "     --disablelocal             don't use locally-defined policy " LOCAL_POLICY_NAME "\n"));
#endif

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
  struct stat st;
  struct authInfoType *authInfo = NULL;
  gboolean nisAvail = FALSE, kerberosAvail = FALSE, ldapAvail = FALSE;

  int back = 0, test = 0, nostart = 0, kickstart = 0, help = 0;

  int enableShadow = 0, disableShadow = 0, enableMD5 = 0, disableMD5 = 0;

  int enableHesiod = 0, disableHesiod = 0;
  char *hesiodLHS = NULL, *hesiodRHS = NULL;

  int enableLDAP = 0, disableLDAP = 0, enableLDAPAuth = 0, disableLDAPAuth = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;

  int enableNIS = 0, disableNIS = 0;
  char *nisServer = NULL, *nisDomain = NULL;

  int enableKrb5 = 0, disableKrb5 = 0;
  char *krb5Realm = NULL, *krb5KDC = NULL, *krb5AdminServer = NULL;

#ifdef LOCAL_POLICIES
  int enableLocal = 0, disableLocal = 0;
#endif

  poptContext optCon;
  const struct poptOption options[] = {
    { "back", '\0', POPT_ARG_NONE, &back, 0, NULL, NULL},
    { "test", '\0', POPT_ARG_NONE, &test, 0, NULL, NULL},
    { "nostart", '\0', POPT_ARG_NONE, &nostart, 0, NULL, NULL},
    { "kickstart", '\0', POPT_ARG_NONE, &kickstart, 0, NULL, NULL},
#ifdef LOCAL_POLICIES
    { "enablelocal", '\0', POPT_ARG_NONE, &enableLocal, 0, NULL, NULL},
    { "disablelocal", '\0', POPT_ARG_NONE, &disableLocal, 0, NULL, NULL},
#endif

    { "useshadow", '\0', POPT_ARG_NONE, &enableShadow, 0, NULL, NULL},
    { "enableshadow", '\0', POPT_ARG_NONE, &enableShadow, 0, NULL, NULL},
    { "disableshadow", '\0', POPT_ARG_NONE, &disableShadow, 0, NULL, NULL},
    { "enablemd5", '\0', POPT_ARG_NONE, &enableMD5, 0, NULL, NULL},
    { "disablemd5", '\0', POPT_ARG_NONE, &disableMD5, 0, NULL, NULL},

    { "enablehesiod", '\0', POPT_ARG_NONE, &enableHesiod, 0, NULL, NULL},
    { "disablehesiod", '\0', POPT_ARG_NONE, &disableHesiod, 0, NULL, NULL},
    { "hesiodlhs", '\0', POPT_ARG_STRING, &hesiodLHS, 0, NULL, NULL},
    { "hesiodrhs", '\0', POPT_ARG_STRING, &hesiodRHS, 0, NULL, NULL},

    { "enableldap", '\0', POPT_ARG_NONE, &enableLDAP, 0, NULL, NULL},
    { "disableldap", '\0', POPT_ARG_NONE, &disableLDAP, 0, NULL, NULL},
    { "enableldapauth", '\0', POPT_ARG_NONE, &enableLDAPAuth, 0, NULL, NULL},
    { "disableldapauth", '\0', POPT_ARG_NONE, &disableLDAPAuth, 0, NULL, NULL},
    { "ldapserver", '\0', POPT_ARG_STRING, &ldapServer, 0, NULL, NULL},
    { "ldapbasedn", '\0', POPT_ARG_STRING, &ldapBaseDN, 0, NULL, NULL},

    { "enablekrb5", '\0', POPT_ARG_NONE, &enableKrb5, 0, NULL, NULL},
    { "disablekrb5", '\0', POPT_ARG_NONE, &disableKrb5, 0, NULL, NULL},
    { "krb5realm", '\0', POPT_ARG_STRING, &krb5Realm, 0, NULL, NULL},
    { "krb5kdc", '\0', POPT_ARG_STRING, &krb5KDC, 0, NULL, NULL},
    { "krb5adminserver", '\0', POPT_ARG_STRING, &krb5AdminServer, 0, NULL, NULL},

    { "enablenis", '\0', POPT_ARG_NONE, &enableNIS, 0, NULL, NULL},
    { "disablenis", '\0', POPT_ARG_NONE, &disableNIS, 0, NULL, NULL},
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
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "hesiod.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadKerberos(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/krb5.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "krb5.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadLDAP(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/ldap.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "ldap.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadNIS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/yp.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "yp.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadNSS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/nsswitch.conf", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "nsswitch.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadNetwork(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/sysconfig/network", R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "sysconfig/network");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadPAM(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, R_OK)) {
      fprintf(stderr, i18n("%s: critical error reading %s/%s"),
	      progName, SYSCONFDIR, "pam.d/" AUTH_PAM_SERVICE);
      fprintf(stderr, ": %s\n", strerror(errno));
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

#ifdef LOCAL_POLICIES
  overrideBoolean(&authInfo->enableLocal, enableLocal, disableLocal);
#endif

  overrideBoolean(&authInfo->enableShadow, enableShadow, disableShadow);
  overrideBoolean(&authInfo->enableMD5, enableMD5, disableMD5);

  overrideBoolean(&authInfo->enableHesiod, enableHesiod, disableHesiod);
  overrideString(&authInfo->hesiodLHS, hesiodLHS);
  overrideString(&authInfo->hesiodRHS, hesiodRHS);

  overrideBoolean(&authInfo->enableLDAP, enableLDAP, disableLDAP);
  overrideBoolean(&authInfo->enableLDAPAuth, enableLDAPAuth, disableLDAPAuth);
  overrideString(&authInfo->ldapServer, ldapServer);
  overrideString(&authInfo->ldapBaseDN, ldapBaseDN);

  overrideBoolean(&authInfo->enableNIS, enableNIS, disableNIS);
  overrideString(&authInfo->nisDomain, nisDomain);
  overrideString(&authInfo->nisServer, nisServer);

  overrideBoolean(&authInfo->enableKerberos, enableKrb5, disableKrb5);
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
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "hesiod.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteKerberos(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "krb5.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteLDAP(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "ldap.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteNIS(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "yp.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteNSS(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "nsswitch.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
    }
    if (authInfoWriteNetwork(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "sysconfig/network");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWritePAM(authInfo) == FALSE) {
      fprintf(stderr, i18n("%s: critical error writing %s/%s"),
	      progName, SYSCONFDIR, "pam.d/" AUTH_PAM_SERVICE);
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    toggleShadow(authInfo);
    toggleNisService(authInfo->enableNIS, authInfo->nisDomain, nostart);
    if((stat(PATH_NSCD_PID, &st) == 0) && !nostart) {
      system("/sbin/service nscd restart");
    }
  }

  return 0;
}
