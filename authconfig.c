 /*
  * Authconfig - client authentication configuration program
  * Copyright (c) 1999-2003 Red Hat, Inc.
  *
  * Authors: Preston Brown <pbrown@redhat.com>
  *          Nalin Dahyabhai <nalin@redhat.com>
  *          Matt Wilson <msw@redhat.com>
  * Current maintainer: Nalin Dahyabhai <nalin@redhat.com>
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
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <newt.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include "authinfo.h"
#ifdef LOCAL_POLICIES
#include "localpol.h"
#endif

struct warntype {
  const char *path, *service, *package;
  struct warntype *next;
};
struct callbacktype {
  void (*callback)(newtComponent, void*);
  void *data;
  struct callbacktype *next;
};
static struct callbacktype *
createCallbackListItem(void *callback, void *data, struct callbacktype *next)
{
  struct callbacktype *ret;
  ret = g_malloc(sizeof(struct callbacktype));
  ret->callback = callback;
  ret->data = data;
  ret->next = next;
  return ret;
}
static void
runCallbackList(newtComponent comp, void *cblist)
{
  struct callbacktype *i;
  i = cblist;
  while (i != NULL) {
    if (i->callback) {
      i->callback(comp, i->data);
    }
    i = i->next;
  }
}

/*
 * A newt callback to disallow spaces in an entry field.
 */
static int
entryFilter(newtComponent entry, void * data, int ch, int cursor)
{
    if ((ch == ' ') || (ch == '\t'))
	return 0;
    return ch;
}

static void
overrideBoolean(gboolean *dest, int switch_on, int switch_off)
{
  if (switch_on) *dest = TRUE;
  if (switch_off) *dest = FALSE;
}

static void
setString(char **dest, const char *source)
{
  if (*dest != NULL) {
    g_free(*dest);
  }
  *dest = g_strdup(source);
}

static void
overrideString(char **dest, const char *source)
{
  if (source != NULL) {
    setString(dest, source);
  }
}

enum datatype {lvalue, tfvalue, svalue, rvalue};
struct formdata {
	enum datatype type;
	const char *description;
	size_t offset;
	char **r_valid_values;
	gboolean s_invisible;
};

static gboolean
getGenericChoices(const char *dialogTitle,
		  int n_items, struct formdata *items,
		  struct authInfoType *authInfo,
		  const char *anotherText,
		  gboolean (*anotherCb)(struct authInfoType *),
		  const char *cancelText, const char *okText)
{
  newtComponent form, ok, cancel, another, comp, cb, result;
  newtGrid mainGrid, questionGrid, buttonGrid, radioGrid;
  GPtrArray **radios;
  const char **strings;
  char *booleans;
  gboolean *b;
  char **s;
  int i, j, row, rows, def;

  radios = g_malloc(n_items * sizeof(GPtrArray *));
  for (i = 0; i < n_items; i++) {
    radios[i] = NULL;
  }
  strings = g_malloc0(n_items * sizeof(char*));
  booleans = g_malloc0(n_items);

  /* Count up the number of rows we need in the grid. */
  rows = n_items;

  /* Create a grid for these questions. */
  questionGrid = newtCreateGrid(2, rows);
  row = 0;
  for (i = 0; i < n_items; i++) {
    switch (items[i].type) {
    case tfvalue:
      b = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
      cb = newtCheckbox(-1, -1, items[i].description,
		        *b ? '*' : ' ',
		        NULL, &booleans[i]);
      newtGridSetField(questionGrid, 0, row, NEWT_GRID_COMPONENT,
     		       newtLabel(-1, -1, ""),
                       0, 0, 0, 0, NEWT_ANCHOR_RIGHT, 0);
      newtGridSetField(questionGrid, 1, row, NEWT_GRID_COMPONENT, cb,
                       0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
      row++;
      break;
    case svalue:
      s = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
      comp = newtLabel(-1, -1, items[i].description);
      newtGridSetField(questionGrid, 0, row, NEWT_GRID_COMPONENT, comp,
                       0, 0, 1, 0, NEWT_ANCHOR_RIGHT, 0);
      comp = newtEntry(-1, -1, *s ? *s : "", 40, &(strings[i]),
                       NEWT_ENTRY_SCROLL |
		       (items[i].s_invisible ? NEWT_ENTRY_HIDDEN : 0));
      newtEntrySetFilter(comp, entryFilter, NULL);
      newtGridSetField(questionGrid, 1, row, NEWT_GRID_COMPONENT, comp,
                       0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);
      row++;
      break;
    case rvalue:
      s = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
      comp = newtLabel(-1, -1, items[i].description);
      newtGridSetField(questionGrid, 0, row, NEWT_GRID_COMPONENT, comp,
                       0, 0, 1, 0, NEWT_ANCHOR_TOP | NEWT_ANCHOR_RIGHT, 0);
      for (j = 0; items[i].r_valid_values[j] != NULL; j++) /* nothing */;
      radioGrid = newtCreateGrid(1, j);
      radios[i] = g_ptr_array_new();
      /* figure out which radio button to make the default */
      def = 0;
      for (j = 0; items[i].r_valid_values[j] != NULL; j++) {
	if (strcmp(*s, items[i].r_valid_values[j]) == 0) {
	  def = j;
	}
      }
      /* save the button and its string */
      for (j = 0; items[i].r_valid_values[j] != NULL; j++) {
        comp = newtRadiobutton(-1, -1, items[i].r_valid_values[j],
			       j == def,
			       j == 0 ? NULL : comp);
	g_ptr_array_add(radios[i], comp);
	g_ptr_array_add(radios[i], items[i].r_valid_values[j]);
        newtGridSetField(radioGrid, 0, j, NEWT_GRID_COMPONENT, comp,
                         0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
      }
      newtGridSetField(questionGrid, 1, row, NEWT_GRID_SUBGRID, radioGrid,
                       0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
      row++;
      break;
    case lvalue:
      comp = newtTextboxReflowed(0, 0, (char*) items[i].description,
				 50, 1, 1, 0);
      newtGridSetField(questionGrid, 0, row, NEWT_GRID_COMPONENT, comp,
                       0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
      row++;
      break;
    }
  }
  g_assert(row == rows);

  /* Buttons. */
  buttonGrid = newtCreateGrid(anotherText ? 3 : 2, 1);
  cancel = newtButton(-1, -1, cancelText);
  ok = newtButton(-1, -1, okText);
  another = anotherText ? newtButton(-1, -1, anotherText) : NULL;
  newtGridSetField(buttonGrid, 0, 0, NEWT_GRID_COMPONENT, cancel,
		   0, 0, 0, 0, 0, 0);
  if (anotherText) {
    newtGridSetField(buttonGrid, 1, 0, NEWT_GRID_COMPONENT, another,
		     0, 0, 0, 0, 0, 0);
  }
  newtGridSetField(buttonGrid, anotherText ? 2 : 1, 0,
		   NEWT_GRID_COMPONENT, ok, 0, 0, 0, 0, 0, 0);

  /* Top-level grid. */
  mainGrid = newtCreateGrid(1, 2);
  newtGridSetField(mainGrid, 0, 0, NEWT_GRID_SUBGRID, questionGrid,
		   0, 0, 0, 1, 0, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, buttonGrid,
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);

  /* Run the form and interpret the results. */
  form = newtForm(NULL, NULL, 0);
  newtGridWrappedWindow(mainGrid, (char*) dialogTitle);
  newtGridAddComponentsToForm(mainGrid, form, 1);

runform:
  result = newtRunForm(form);

  if (result != cancel) {
    for (i = 0; i < n_items; i++) {
      switch (items[i].type) {
      case svalue:
        s = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
	if (*s) {
	  g_free(*s);
	}
	*s = g_strdup(strings[i]);
        break;
      case tfvalue:
        b = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
	*b = (booleans[i] == '*');
        break;
      case rvalue:
        s = G_STRUCT_MEMBER_P(authInfo, items[i].offset);
	if (radios[i]->len > 0) {
	  comp = g_ptr_array_index(radios[i], 0);
	  comp = newtRadioGetCurrent(comp);
	  if (comp != NULL) {
	    for (j = 0; j < radios[i]->len; j += 2) {
	      if (comp == g_ptr_array_index(radios[i], j)) {
	        if (*s) {
		  g_free(*s);
		}
		*s = g_strdup(g_ptr_array_index(radios[i], j + 1));
	      }
	    }
	  }
	}
        break;
      case lvalue:
	break;
      }
    }
  }

  if (result == another) {
    anotherCb(authInfo);
    goto runform;
  }

  newtFormDestroy(form);
  newtPopWindow();

  /* Newt frees any strings. */
  for (i = 0; i < n_items; i++) {
    if (radios[i] != NULL) {
      g_ptr_array_free(radios[i], TRUE);
      radios[i] = NULL;
    }
  }

  g_free(radios);
  g_free(strings);
  g_free(booleans);

  return (result != cancel) ? TRUE : FALSE;
}

static gboolean
getHesiodSettings(struct authInfoType *authInfo, gboolean next)
{
  struct formdata questions[] = {
    {svalue, _("LHS:"),
     G_STRUCT_OFFSET(struct authInfoType, hesiodLHS)},
    {svalue, _("RHS:"),
     G_STRUCT_OFFSET(struct authInfoType, hesiodRHS)},
  };
  return getGenericChoices(_("Hesiod Settings"),
			   G_N_ELEMENTS(questions), questions, authInfo,
			   NULL, NULL, _("Back"), next ? _("Next") : _("Ok"));
}

static gboolean
getLDAPSettings(struct authInfoType *authInfo, gboolean next)
{
  struct formdata questions[] = {
    {tfvalue, _("Use TLS"),
     G_STRUCT_OFFSET(struct authInfoType, enableLDAPS)},
    {svalue, _("Server:"),
     G_STRUCT_OFFSET(struct authInfoType, ldapServer)},
    {svalue, _("Base DN:"),
     G_STRUCT_OFFSET(struct authInfoType, ldapBaseDN)},
  };
  return getGenericChoices(_("LDAP Settings"),
                           G_N_ELEMENTS(questions), questions, authInfo,
			   NULL, NULL, _("Back"), next ? _("Next") : _("Ok"));
}

static gboolean
getNISSettings(struct authInfoType *authInfo, gboolean next)
{
  struct formdata questions[] = {
    {svalue, _("Domain:"),
     G_STRUCT_OFFSET(struct authInfoType, nisDomain)},
    {svalue, _("Server:"),
     G_STRUCT_OFFSET(struct authInfoType, nisServer)},
  };
  return getGenericChoices(_("NIS Settings"),
			   G_N_ELEMENTS(questions), questions, authInfo,
			   NULL, NULL, _("Back"), next ? _("Next") : _("Ok"));
}

static gboolean
getKerberosSettings(struct authInfoType *authInfo, gboolean next)
{
  struct formdata questions[] = {
    {svalue, _("Realm:"),
     G_STRUCT_OFFSET(struct authInfoType, kerberosRealm)},
    {svalue, _("KDC:"),
     G_STRUCT_OFFSET(struct authInfoType, kerberosKDC)},
    {svalue, _("Admin Server:"),
     G_STRUCT_OFFSET(struct authInfoType, kerberosAdminServer)},
    {tfvalue, _("Use DNS to resolve hosts to realms"),
     G_STRUCT_OFFSET(struct authInfoType, kerberosRealmviaDNS)},
    {tfvalue, _("Use DNS to locate KDCs for realms"),
     G_STRUCT_OFFSET(struct authInfoType, kerberosKDCviaDNS)},
  };
  return getGenericChoices(_("Kerberos Settings"),
                           G_N_ELEMENTS(questions), questions, authInfo,
			   NULL, NULL, _("Back"), next ? _("Next") : _("Ok"));
}

static gboolean
getSMBSettings(struct authInfoType *authInfo, gboolean next)
{
  struct formdata questions[] = {
    {svalue, _("Workgroup:"),
     G_STRUCT_OFFSET(struct authInfoType, smbWorkgroup)},
    {svalue, _("Servers:"),
     G_STRUCT_OFFSET(struct authInfoType, smbServers)},
    {svalue, _("Shell:"),
     G_STRUCT_OFFSET(struct authInfoType, winbindTemplateShell)},
  };
  return getGenericChoices(_("SMB Settings"),
			   G_N_ELEMENTS(questions), questions, authInfo,
			   NULL, NULL, _("Back"), next ? _("Next") : _("Ok"));
}

static gboolean
getJoinSettings(struct authInfoType *authInfo)
{
  gboolean ret;
  struct formdata questions[] = {
    {svalue, _("Domain Administrator:"),
     G_STRUCT_OFFSET(struct authInfoType, joinUser)},
    {svalue, _("Password:"),
     G_STRUCT_OFFSET(struct authInfoType, joinPassword), NULL, TRUE},
  };
  if (authInfo->joinUser) {
    g_free(authInfo->joinUser);
  }
  authInfo->joinUser = g_strdup("Administrator");
  ret = getGenericChoices(_("Join Settings"),
			  G_N_ELEMENTS(questions), questions, authInfo,
			  NULL, NULL, _("Cancel"), _("Ok"));
  if (ret == TRUE) {
    newtSuspend();
    authInfoUpdate(authInfo);
    authInfoWrite(authInfo);
    authInfoJoin(authInfo, TRUE);
    newtResume();
  }
  return TRUE;
}

static gboolean
maybeGetJoinSettings(struct authInfoType *authInfo)
{
  gboolean ret;
  struct authInfoType *originalInfo;
  struct formdata questions[] = {
    {lvalue, _("Some of the configuration changes you've made should be saved to disk before continuing.  If you do not save them, then your attempt to join the domain may fail.  Save changes?"),},
  };
  originalInfo = authInfoRead();
  authInfoUpdate(originalInfo);
  authInfoUpdate(authInfo);
  if (authInfoDiffers(authInfo, originalInfo)) {
    ret = getGenericChoices(_("Save Settings"),
			    G_N_ELEMENTS(questions), questions, authInfo,
			    NULL, NULL, _("No"), _("Yes"));
    if (ret == TRUE) {
      authInfoWrite(authInfo);
      getJoinSettings(authInfo);
    }
  } else {
    getJoinSettings(authInfo);
  }
  authInfoFree(originalInfo);
  return TRUE;
}


static gboolean
getWinbindSettings(struct authInfoType *authInfo, gboolean next)
{
  const char *security[] = {
    "ads", "domain", NULL,
  };
  const char *candidates[] = {
    "/sbin/nologin", "/bin/sh", "/bin/bash", "/bin/tcsh", "/bin/ksh",
    "/bin/zsh",
  };
  /* Why does your favorite shell not show up in the list?  Because it won't
   * fit, that's why! */
  const char *shells[6];
  int i, j;
  struct formdata questions[] = {
    {rvalue, _("Security Model:"),
     G_STRUCT_OFFSET(struct authInfoType, smbSecurity), (char**) security},
    {svalue, _("Domain:"),
     G_STRUCT_OFFSET(struct authInfoType, smbWorkgroup)},
    {svalue, _("Domain Controllers:"),
     G_STRUCT_OFFSET(struct authInfoType, smbServers)},
    {svalue, _("ADS Realm:"),
     G_STRUCT_OFFSET(struct authInfoType, smbRealm)},
    {rvalue, _("Template Shell:"),
     G_STRUCT_OFFSET(struct authInfoType, winbindTemplateShell), (char**) shells},
  };
  i = 0;
  if ((authInfo->winbindTemplateShell != NULL) &&
      (strlen(authInfo->winbindTemplateShell) > 0)) {
    shells[i++] = g_strdup(authInfo->winbindTemplateShell); /* XXX */
  }
  for (j = 0;
       (j < G_N_ELEMENTS(candidates)) && (i < (G_N_ELEMENTS(shells) - 1));
       j++) {
    if ((shells[0] == NULL) || (strcmp(shells[0], candidates[j]) != 0)) {
      if (access(candidates[j], X_OK) == 0) {
        shells[i++] = candidates[j];
      }
    }
  }
  shells[i] = NULL;
  return getGenericChoices(_("Winbind Settings"),
			   G_N_ELEMENTS(questions), questions, authInfo,
			   _("Join Domain"), maybeGetJoinSettings,
			   _("Back"), next ? _("Next") : _("Ok"));
}

static void
syncCheckbox(newtComponent comp, void *comp2)
{
  newtComponent second;
  second = comp2;
  if (newtCheckboxGetValue(second) != newtCheckboxGetValue(comp)) {
    newtCheckboxSetValue(second, newtCheckboxGetValue(comp));
  }
}

static void
warnCallback(newtComponent comp, void *warningp)
{
  struct warntype *warning;
  char *p;

  warning = warningp;

  while (warning != NULL) {
    if (access(warning->path, R_OK) != 0) {
      p = g_strdup_printf(AUTHCONFIG_PACKAGE_WARNING,
		          warning->path,
		          warning->service,
		          warning->package);
      newtWinMessage(_("Warning"), _("Ok"), p, NULL);
      g_free(p);
      newtRefresh();
    }
    warning = warning->next;
  }
}

static gboolean
getMainChoices(int back, gboolean nisAvail, gboolean ldapAvail,
	       gboolean kerberosAvail, gboolean smbAvail, gboolean cacheAvail,
	       struct authInfoType *authInfo)
{
  newtComponent form, ok, cancel, comp, cb;
  newtGrid mainGrid, mechGrid, buttonGrid, infoGrid, authGrid;
  char cache, hesiod, ldap, nis, krb5, ldapa, smb, shadow, md5;
  struct warntype warnCache = {PATH_NSCD,
			       _("caching"),
			       "nscd",
			       NULL};
  struct warntype warnKerberos = {PATH_PAM_KRB5,
				  _("Kerberos"),
				  "pam_krb5",
				  NULL};
  struct warntype warnLDAPAuth = {PATH_PAM_LDAP,
				  _("LDAP authentication"),
				  "nss_ldap",
				  NULL};
  struct warntype warnLDAP = {PATH_LIBNSS_LDAP,
			      _("LDAP"),
			      "nss_ldap",
			      NULL};
  struct warntype warnNIS = {PATH_YPBIND,
			     _("NIS"),
			     "ypbind",
			     NULL};
  struct warntype warnShadow = {PATH_PWCONV,
			        _("shadow password"),
				"shadow-utils",
				NULL};
  struct warntype warnSMB = {PATH_PAM_SMB,
			     _("SMB authentication"),
			     "pam_smb",
			     NULL};
  struct warntype warnWinbindNet = {PATH_WINBIND_NET,
				    _("Winbind"),
				    "samba-client",
				    NULL};
  struct warntype warnWinbindAuth = {PATH_PAM_WINBIND,
				     _("Winbind authentication"),
				     "samba-client",
				     &warnWinbindNet};
  struct warntype warnWinbind = {PATH_LIBNSS_WINBIND,
				 _("Winbind"),
				 "samba-client",
				 &warnWinbindNet};
  struct {
    newtComponent a, b;
  } matched[] = {
    {NULL, NULL},
  };

  /* Information. */
  infoGrid = newtCreateGrid(1, 6);
  comp = newtLabel(-1, -1, _("User Information"));
  newtGridSetField(infoGrid, 0, 0, NEWT_GRID_COMPONENT, comp,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  cb = newtCheckbox(-1, -1, _("Cache Information"),
		    authInfo->enableCache ? '*' : ' ',
		    NULL, &cache);
  newtGridSetField(infoGrid, 0, 1, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnCache);

  cb = newtCheckbox(-1, -1, _("Use Hesiod"),
		    authInfo->enableHesiod ? '*' : ' ',
		    NULL, &hesiod);
  newtGridSetField(infoGrid, 0, 2, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  cb = newtCheckbox(-1, -1, _("Use LDAP"),
		    authInfo->enableLDAP ? '*' : ' ',
		    NULL, &ldap);
  newtGridSetField(infoGrid, 0, 3, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnLDAP);

  cb = newtCheckbox(-1, -1, _("Use NIS"),
		    authInfo->enableNIS ? '*' : ' ',
		    NULL, &nis);
  newtGridSetField(infoGrid, 0, 4, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnNIS);

  cb = newtCheckbox(-1, -1, _("Use Winbind"),
		    authInfo->enableWinbind ? '*' : ' ',
		    NULL, NULL);
  newtGridSetField(infoGrid, 0, 5, NEWT_GRID_COMPONENT, cb,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  matched[0].a = cb;

  /* Authentication. */
  authGrid = newtCreateGrid(1, 7);

  comp = newtLabel(-1, -1, _("Authentication"));
  newtGridSetField(authGrid, 0, 0, NEWT_GRID_COMPONENT, comp,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  cb = newtCheckbox(-1, -1, _("Use MD5 Passwords"),
		    authInfo->enableMD5 ? '*' : ' ',
		    NULL, &md5);
  newtGridSetField(authGrid, 0, 1, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);

  cb = newtCheckbox(-1, -1, _("Use Shadow Passwords"),
		    authInfo->enableShadow ? '*' : ' ',
		    NULL, &shadow);
  newtGridSetField(authGrid, 0, 2, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnShadow);

  cb = newtCheckbox(-1, -1, _("Use LDAP Authentication"),
		    authInfo->enableLDAP ? '*' : ' ',
		    NULL, &ldapa);
  newtGridSetField(authGrid, 0, 3, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnLDAPAuth);

  cb = newtCheckbox(-1, -1, _("Use Kerberos"),
		    authInfo->enableKerberos ? '*' : ' ',
		    NULL, &krb5);
  newtGridSetField(authGrid, 0, 4, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnKerberos);

  cb = newtCheckbox(-1, -1, _("Use SMB Authentication"),
		    authInfo->enableSMB ? '*' : ' ',
		    NULL, &smb);
  newtGridSetField(authGrid, 0, 5, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  newtComponentAddCallback(cb, warnCallback, &warnSMB);

  cb = newtCheckbox(-1, -1, _("Use Winbind Authentication"),
		    authInfo->enableWinbind ? '*' : ' ',
		    NULL, NULL);
  newtGridSetField(authGrid, 0, 6, NEWT_GRID_COMPONENT, cb,
		   1, 0, 0, 0, NEWT_ANCHOR_LEFT, NEWT_GRID_FLAG_GROWX);
  matched[0].b = cb;

  /* Make sure that the checkboxes have the same value. */
  newtComponentAddCallback(matched[0].a,
  			   runCallbackList,
			   createCallbackListItem(syncCheckbox, matched[0].b,
			   createCallbackListItem(warnCallback, &warnWinbind,
			   NULL)));
  newtComponentAddCallback(matched[0].b,
  			   runCallbackList,
			   createCallbackListItem(syncCheckbox, matched[0].a,
			   createCallbackListItem(warnCallback, &warnWinbindAuth,
			   NULL)));

  /* Control grid. */
  mechGrid = newtCreateGrid(2, 1);
  newtGridSetField(mechGrid, 0, 0, NEWT_GRID_SUBGRID, infoGrid,
		   1, 0, 1, 1, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(mechGrid, 1, 0, NEWT_GRID_SUBGRID, authGrid,
		   1, 0, 1, 1, NEWT_ANCHOR_RIGHT, 0);

  /* Buttons. */
  buttonGrid = newtCreateGrid(2, 1);
  cancel = newtButton(-1, -1, back ? _("Back") : _("Cancel"));
  ok = newtButton(-1, -1, _("Next"));
  newtGridSetField(buttonGrid, 0, 0, NEWT_GRID_COMPONENT, cancel,
		   0, 0, 0, 0, 0, 0);
  newtGridSetField(buttonGrid, 1, 0, NEWT_GRID_COMPONENT, ok,
		   0, 0, 0, 0, 0, 0);

  /* Top-level grid. */
  mainGrid = newtCreateGrid(1, 2);
  newtGridSetField(mainGrid, 0, 0, NEWT_GRID_SUBGRID, mechGrid,
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);
  newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, buttonGrid,
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);

  /* Run the form and interpret the results. */
  form = newtForm(NULL, NULL, 0);
  newtGridWrappedWindow(mainGrid, _("Authentication Configuration"));
  newtGridAddComponentsToForm(mainGrid, form, 1);

  /* BEHOLD!  AUTHCONFIG IN ALL ITS GORY GLORY! */
  comp = newtRunForm(form);

  if (comp != cancel) {
    authInfo->enableCache = (cache == '*');
    authInfo->enableHesiod = (hesiod == '*');
    authInfo->enableLDAP = (ldap == '*');
    authInfo->enableNIS = (nis == '*');
    authInfo->enableWinbind = (newtCheckboxGetValue(matched[0].a) == '*');
    authInfo->enableShadow = (shadow == '*');
    authInfo->enableMD5 = (md5 == '*');
    authInfo->enableLDAPAuth = (ldapa == '*');
    authInfo->enableKerberos = (krb5 == '*');
    authInfo->enableSMB = (smb == '*');
  }

  newtFormDestroy(form);
  newtPopWindow();

  return (comp != cancel) ? TRUE : FALSE;
}

static int
getChoices(int back, gboolean nisAvail, gboolean ldapAvail,
	   gboolean kerberosAvail, gboolean smbAvail, gboolean cacheAvail,
	   struct authInfoType *authInfo)
{
  int next = 1;
  gboolean rc = FALSE, more;
  while ((next > 0) && (next <= 7)) {
    authInfoUpdate(authInfo);
    switch (next) {
    case 1:
      rc = getMainChoices(back, nisAvail, ldapAvail, kerberosAvail,
			  smbAvail, cacheAvail, authInfo);
      break;
    case 2:
      if (authInfo->enableHesiod) {
        more = authInfo->enableLDAP ||
	       authInfo->enableLDAPAuth ||
	       authInfo->enableKerberos ||
	       authInfo->enableNIS ||
	       authInfo->enableSMB ||
	       authInfo->enableWinbind;
        rc = getHesiodSettings(authInfo, more);
      }
      break;
    case 3:
      if (authInfo->enableLDAP || authInfo->enableLDAPAuth) {
        more = authInfo->enableKerberos ||
	       authInfo->enableNIS ||
	       authInfo->enableSMB ||
	       authInfo->enableWinbind;
        rc = getLDAPSettings(authInfo, more);
      }
      break;
    case 4:
      if (authInfo->enableNIS) {
        more = authInfo->enableKerberos ||
	       authInfo->enableSMB ||
	       authInfo->enableWinbind;
        rc = getNISSettings(authInfo, more);
      }
      break;
    case 5:
      if (authInfo->enableKerberos) {
        more = authInfo->enableSMB ||
	       authInfo->enableWinbind;
        rc = getKerberosSettings(authInfo, more);
      }
      break;
    case 6:
      if (authInfo->enableSMB && !authInfo->enableWinbind) {
        more = authInfo->enableWinbind;
        rc = getSMBSettings(authInfo, more);
      }
      break;
    case 7:
      if (authInfo->enableWinbind) {
        more = FALSE;
        rc = getWinbindSettings(authInfo, more);
      }
      break;
    default:
      g_assert_not_reached();
      break;
    }
    authInfoUpdate(authInfo);
    if (rc) {
      next++;
    } else {
      next--;
    }
  }
  return (next == 8);
}


static gboolean
fileInaccessible(const char *path, int perms)
{
  struct stat st;
  if(stat(path, &st) == 0) {
    return (access(path, perms) == -1);
  } else {
    return (errno != ENOENT);
  }
}

int
main(int argc, const char **argv)
{
  int rc;
  struct authInfoType *authInfo = NULL;
  gboolean nisAvail = FALSE, kerberosAvail = FALSE, ldapAvail = FALSE,
	   smbAvail = FALSE, cacheAvail = FALSE;

  int back = 0, test = 0, nostart = 0, kickstart = 0;

  int enableShadow = 0, disableShadow = 0, enableMD5 = 0, disableMD5 = 0;

  int enableHesiod = 0, disableHesiod = 0;
  char *hesiodLHS = NULL, *hesiodRHS = NULL;

  int enableLDAP = 0, enableLDAPS = 0, disableLDAP = 0, disableLDAPS = 0,
      enableLDAPAuth = 0, disableLDAPAuth = 0;
  char *ldapServer = NULL, *ldapBaseDN = NULL;

  int enableNIS = 0, disableNIS = 0;
  char *nisServer = NULL, *nisDomain = NULL;

  int enableKrb5 = 0, disableKrb5 = 0;
  char *krb5Realm = NULL, *krb5KDC = NULL, *krb5AdminServer = NULL;
  int enableKrb5RealmDNS = 0, enableKrb5KDCDNS = 0;
  int disableKrb5RealmDNS = 0, disableKrb5KDCDNS = 0;

  int enableSmb = 0, disableSmb = 0;
  char *smbWorkgroup = NULL, *smbServers = NULL, *smbRealm = NULL;

  int enableWinbind = 0, disableWinbind = 0;
  char *smbSecurity = NULL, *smbIdmapUid = NULL, *smbIdmapGid = NULL;

  int enableWinbindUseDefaultDomain = 0, disableWinbindUseDefaultDomain = 0;
  char *winbindSeparator = NULL, *winbindTemplateHomedir = NULL,
       *winbindTemplatePrimaryGroup = NULL, *winbindTemplateShell = NULL;
  char *winbindJoiner = NULL;

  int enableWINS = 0, disableWINS = 0;

  int enableCache = 0, disableCache = 0;

  int probe = 0;

#ifdef LOCAL_POLICIES
  int enableLocal = 0, disableLocal = 0;
#endif

  gboolean badOpt = FALSE;
  poptContext optCon;

  /* first set up our locale info for gettext. */
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, "/usr/share/locale");
  textdomain(PACKAGE);

  {
    const struct poptOption options[] = {
      { "useshadow", '\0', POPT_ARG_NONE, &enableShadow, 0,
	NULL, NULL},
      { "enableshadow", '\0', POPT_ARG_NONE, &enableShadow, 0,
	_("enable shadowed passwords by default"), NULL},
      { "disableshadow", '\0', POPT_ARG_NONE, &disableShadow, 0,
	_("disable shadowed passwords by default"), NULL},
      { "usemd5", '\0', POPT_ARG_NONE, &enableMD5, 0,
	NULL, NULL},
      { "enablemd5", '\0', POPT_ARG_NONE, &enableMD5, 0,
	_("enable MD5 passwords by default"), NULL},
      { "disablemd5", '\0', POPT_ARG_NONE, &disableMD5, 0,
	_("disable MD5 passwords by default\n"), NULL},

      { "enablenis", '\0', POPT_ARG_NONE, &enableNIS, 0,
	_("enable NIS"), NULL},
      { "disablenis", '\0', POPT_ARG_NONE, &disableNIS, 0,
	_("disable NIS"), NULL},
      { "nisdomain", '\0', POPT_ARG_STRING, &nisDomain, 0,
	_("default NIS domain"), _("<domain>")},
      { "nisserver", '\0', POPT_ARG_STRING, &nisServer, 0,
	_("default NIS server\n"), _("<server>")},

      { "enableldap", '\0', POPT_ARG_NONE, &enableLDAP, 0,
	_("enable LDAP for user information by default"), NULL},
      { "disableldap", '\0', POPT_ARG_NONE, &disableLDAP, 0,
	_("disable LDAP for user information by default"), NULL},
      { "enableldaptls", '\0', POPT_ARG_NONE, &enableLDAPS, 0,
	_("enable use of TLS with LDAP"), NULL},
      { "disableldaptls", '\0', POPT_ARG_NONE, &disableLDAPS, 0,
	_("disable use of TLS with LDAP"), NULL},

      /* Blech.  Implemented one way, documented the other way (#115107). */
      { "enableldapssl", '\0', POPT_ARGFLAG_DOC_HIDDEN | POPT_ARG_NONE,
        &enableLDAPS, 0, _("enable use of TLS with LDAP"), NULL},
      { "disableldapssl", '\0', POPT_ARGFLAG_DOC_HIDDEN | POPT_ARG_NONE,
        &disableLDAPS, 0, _("disable use of TLS with LDAP"), NULL},

      { "enableldapauth", '\0', POPT_ARG_NONE, &enableLDAPAuth, 0,
	_("enable LDAP for authentication by default"), NULL},
      { "disableldapauth", '\0', POPT_ARG_NONE, &disableLDAPAuth, 0,
	_("disable LDAP for authentication by default"), NULL},
      { "ldapserver", '\0', POPT_ARG_STRING, &ldapServer, 0,
	_("default LDAP server"), _("<server>")},
      { "ldapbasedn", '\0', POPT_ARG_STRING, &ldapBaseDN, 0,
	_("default LDAP base DN\n"), _("<dn>")},

      { "enablekrb5", '\0', POPT_ARG_NONE, &enableKrb5, 0,
	_("enable kerberos authentication by default"), NULL},
      { "disablekrb5", '\0', POPT_ARG_NONE, &disableKrb5, 0,
	_("disable kerberos authentication by default"), NULL},
      { "krb5kdc", '\0', POPT_ARG_STRING, &krb5KDC, 0,
	_("default kerberos KDC"), _("<server>")},
      { "krb5adminserver", '\0', POPT_ARG_STRING, &krb5AdminServer, 0,
	_("default kerberos admin server"), _("<server>")},
      { "krb5realm", '\0', POPT_ARG_STRING, &krb5Realm, 0,
	_("default kerberos realm\n"), _("<realm>")},

      { "enablekrb5kdcdns", '\0', POPT_ARG_NONE, &enableKrb5KDCDNS, 0,
	_("enable use of DNS to find kerberos KDCs"), NULL},
      { "disablekrb5kdcdns", '\0', POPT_ARG_NONE, &disableKrb5KDCDNS, 0,
	_("disable use of DNS to find kerberos KDCs"), NULL},
      { "enablekrb5realmdns", '\0', POPT_ARG_NONE, &enableKrb5RealmDNS, 0,
	_("enable use of DNS to find kerberos realms"), NULL},
      { "disablekrb5realmdns", '\0', POPT_ARG_NONE, &disableKrb5RealmDNS, 0,
	_("disable use of DNS to find kerberos realms\n"), NULL},

      { "enablesmbauth", '\0', POPT_ARG_NONE, &enableSmb, 0,
	_("enable SMB authentication by default"), NULL},
      { "disablesmbauth", '\0', POPT_ARG_NONE, &disableSmb, 0,
	_("disable SMB authentication by default"), NULL},
      { "smbworkgroup", '\0', POPT_ARG_STRING, &smbWorkgroup, 0,
	_("workgroup authentication servers are in"), _("<workgroup>")},
      { "smbservers", '\0', POPT_ARG_STRING, &smbServers, 0,
	_("names of servers to authenticate against\n"), _("<server>")},

      { "enablewinbind", '\0', POPT_ARG_NONE, &enableWinbind, 0,
	_("enable winbind for user information and authentication by default"),
	NULL},
      { "disablewinbind", '\0', POPT_ARG_NONE, &disableWinbind, 0,
	_("disable winbind for user information and authentication by default"),
	NULL},
      { "smbsecurity", '\0', POPT_ARG_STRING, &smbSecurity, 0,
	_("security mode to use for samba and winbind"), "<user|server|domain|ads>"},
      { "smbrealm", '\0', POPT_ARG_STRING, &smbRealm, 0,
	_("default realm for samba and winbind when security=ads"), NULL},
      { "smbidmapuid", '\0', POPT_ARG_STRING, &smbIdmapUid, 0,
	_("uid range winbind will assign to domain or ads users"),
	_("<lowest-highest>")},
      { "smbidmapgid", '\0', POPT_ARG_STRING, &smbIdmapGid, 0,
	_("gid range winbind will assign to domain or ads users"),
	_("<lowest-highest>")},

      { "winbindseparator", '\0', POPT_ARG_STRING, &winbindSeparator, 0,
	_("the character which will be used to separate the domain and user part of winbind-created user names if winbindusedefaultdomain is not enabled"),
	"<\\>"},
      { "winbindtemplatehomedir", '\0', POPT_ARG_STRING,
        &winbindTemplateHomedir, 0,
	_("the directory which winbind-created users will have as home directories"),
	"</home/%D/%U>"},
      { "winbindtemplateprimarygroup", '\0', POPT_ARG_STRING,
        &winbindTemplatePrimaryGroup, 0,
	_("the group which winbind-created users will have as their primary group"),
	"<nobody>"},
      { "winbindtemplateshell", '\0', POPT_ARG_STRING, &winbindTemplateShell, 0,
	_("the shell which winbind-created users will have as their login shell"),
	"</bin/false>"},
      { "enablewinbindusedefaultdomain", '\0', POPT_ARG_NONE,
        &enableWinbindUseDefaultDomain, 0,
	_("configures winbind to assume that users with no domain in their user names are domain users"),
	NULL},
      { "disablewinbindusedefaultdomain", '\0', POPT_ARG_NONE,
        &disableWinbindUseDefaultDomain, 0,
	_("configures winbind to assume that users with no domain in their user names are not domain users"),
	NULL},
      { "winbindjoin", '\0', POPT_ARG_STRING,
        &winbindJoiner, 0,
	_("join the winbind domain or ads realm now as this administrator\n"),
	"<Administrator>"},

      { "enablewins", '\0', POPT_ARG_NONE,
        &enableWINS, 0, _("enable wins for hostname resolution"), NULL},
      { "disablewins", '\0', POPT_ARG_NONE,
        &disableWINS, 0, _("disable wins for hostname resolution\n"), NULL},

      { "enablehesiod", '\0', POPT_ARG_NONE, &enableHesiod, 0,
	_("enable hesiod for user information by default"), NULL},
      { "disablehesiod", '\0', POPT_ARG_NONE, &disableHesiod, 0,
	_("disable hesiod for user information by default"), NULL},
      { "hesiodlhs", '\0', POPT_ARG_STRING, &hesiodLHS, 0,
	_("default hesiod LHS"), _("<lhs>")},
      { "hesiodrhs", '\0', POPT_ARG_STRING, &hesiodRHS, 0,
	_("default hesiod RHS\n"), _("<rhs>")},

      { "enablecache", '\0', POPT_ARG_NONE, &enableCache, 0,
	_("enable caching of user information by default"), NULL},
      { "disablecache", '\0', POPT_ARG_NONE, &disableCache, 0,
	_("disable caching of user information by default\n"), NULL},

      { "back", '\0', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &back, 0,
	NULL, NULL},
      { "test", '\0', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &test, 0,
	NULL, NULL},
      { "nostart", '\0', POPT_ARG_NONE, &nostart, 0,
	_("do not start/stop portmap, ypbind, and nscd"), NULL},
      { "kickstart", '\0', POPT_ARG_NONE, &kickstart, 0,
	_("don't display user interface"), NULL},
      { "probe", '\0', POPT_ARG_NONE, &probe, 0,
	_("probe network for defaults and print them"), NULL},
#ifdef LOCAL_POLICIES
      { "enablelocal", '\0', POPT_ARG_NONE, &enableLocal, 0,
	_("use locally-defined policies"), NULL},
      { "disablelocal", '\0', POPT_ARG_NONE, &disableLocal, 0,
	_("don't use locally-defined policies"), NULL},
#endif
      POPT_AUTOHELP { 0, 0, 0, 0, 0, 0 },
    };

    /* next, process cmd. line options */
    optCon = poptGetContext(PACKAGE, argc, argv, options, 0);
    poptReadDefaultConfig(optCon, 1);
  }

  while ((rc = poptGetNextOpt(optCon)) != -1) {
    fprintf(stderr, _("%s: bad argument %s: %s\n"),
	    PACKAGE, poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
	    poptStrerror(rc));
    badOpt = TRUE;
  }
  if(badOpt) {
    if(!kickstart) {
      return 2;
    }
    fprintf(stderr, _("%s: attempting to continue\n"), PACKAGE);
  }

  if (poptGetArg(optCon)) {
    fprintf(stderr, _("%s: unexpected argument\n"),
	    PACKAGE);
    return 2;
  }

  poptFreeContext(optCon);

  /* if the probe parameter wasn't passed, probe for everything we can
   * figure out using DNS or other means */
  if (probe) {
    authInfo = authInfoProbe();
    if (authInfo->hesiodLHS && authInfo->hesiodRHS) {
      printf("hesiod %s/%s\n",
	     authInfo->hesiodLHS,
             authInfo->hesiodRHS);
    }
    if (authInfo->ldapServer && authInfo->ldapBaseDN) {
      printf("ldap %s/%s\n",
	     authInfo->ldapServer,
	     authInfo->ldapBaseDN);
    }
    if (authInfo->kerberosRealm) {
      printf("krb5 %s/%s/%s\n",
	     authInfo->kerberosRealm,
	     authInfo->kerberosKDC ?: "",
             authInfo->kerberosAdminServer ?: "");
    }
    return 0;
  }

  /* if the test parameter wasn't passed, give an error if not root */
  if (!test && !probe && getuid()) {
    fprintf(stderr, _("%s: can only be run as root\n"),
	    PACKAGE);
    return 2;
  }

  /* allocate memory for the auth info structure */
  authInfo = g_malloc0(sizeof(struct authInfoType));

  /* read the values from the configuration files */
  if (authInfoReadHesiod(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/hesiod.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/hesiod.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadKerberos(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/krb5.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/krb5.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadLDAP(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/ldap.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/ldap.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadNIS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/yp.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/yp.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadSMB(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/pam_smb.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/pam_smb.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadWinbind(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/samba/smb.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/samba/smb.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadNSS(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/nsswitch.conf", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/nsswitch.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadCache(authInfo) == FALSE) {
    fprintf(stderr, _("%s: unable to read caching configuration"), PACKAGE);
    fprintf(stderr, ": %s\n", strerror(errno));
    return 2;
  }
  if (authInfoReadNetwork(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/sysconfig/network", R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/sysconfig/network");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }
  if (authInfoReadPAM(authInfo) == FALSE) {
    if (fileInaccessible(SYSCONFDIR "/pam.d/" AUTH_PAM_SERVICE, R_OK)) {
      fprintf(stderr, _("%s: critical error reading %s/%s"),
	      PACKAGE, SYSCONFDIR, "/pam.d/" AUTH_PAM_SERVICE);
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
  }

  authInfoUpdate(authInfo);

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
  if (access(PATH_PAM_SMB, X_OK) == 0) {
    smbAvail = TRUE;
  }
  if (access(PATH_NSCD, X_OK) == 0) {
    cacheAvail = TRUE;
  }

#ifdef LOCAL_POLICIES
  overrideBoolean(&authInfo->enableLocal, enableLocal, disableLocal);
#endif

  overrideBoolean(&authInfo->enableShadow, enableShadow, disableShadow);
  overrideBoolean(&authInfo->enableMD5, enableMD5, disableMD5);

  overrideBoolean(&authInfo->enableCache, enableCache, disableCache);

  overrideBoolean(&authInfo->enableHesiod, enableHesiod, disableHesiod);
  overrideString(&authInfo->hesiodLHS, hesiodLHS);
  overrideString(&authInfo->hesiodRHS, hesiodRHS);

  overrideBoolean(&authInfo->enableLDAP, enableLDAP, disableLDAP);
  overrideBoolean(&authInfo->enableLDAPS, enableLDAPS, disableLDAPS);
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
  overrideBoolean(&authInfo->kerberosKDCviaDNS,
 		  enableKrb5KDCDNS, disableKrb5KDCDNS);
  overrideBoolean(&authInfo->kerberosRealmviaDNS,
 		  enableKrb5RealmDNS, disableKrb5RealmDNS);

  overrideBoolean(&authInfo->enableSMB, enableSmb, disableSmb);
  overrideString(&authInfo->smbWorkgroup, smbWorkgroup);
  overrideString(&authInfo->smbServers, smbServers);

  overrideBoolean(&authInfo->enableWinbind, enableWinbind, disableWinbind);
  overrideString(&authInfo->smbSecurity, smbSecurity);
  overrideString(&authInfo->smbRealm, smbRealm);
  overrideString(&authInfo->smbIdmapUid, smbIdmapUid);
  overrideString(&authInfo->smbIdmapGid, smbIdmapGid);
  overrideString(&authInfo->winbindSeparator, winbindSeparator);
  overrideString(&authInfo->winbindTemplateHomedir, winbindTemplateHomedir);
  overrideString(&authInfo->winbindTemplatePrimaryGroup,
		 winbindTemplatePrimaryGroup);
  overrideString(&authInfo->winbindTemplateShell, winbindTemplateShell);
  overrideBoolean(&authInfo->winbindUseDefaultDomain,
		  enableWinbindUseDefaultDomain,
		  disableWinbindUseDefaultDomain);

  overrideBoolean(&authInfo->enableWINS, enableWINS, disableWINS);

  authInfoUpdate(authInfo);

  if (!kickstart) {
    char packageVersion[] = PACKAGE " " VERSION " - ";
    newtInit();
    newtCls();

    newtPushHelpLine(_(" <Tab>/<Alt-Tab> between elements   |   <Space> selects   |  <F12> next screen"));
    newtDrawRootText(0, 0, packageVersion);
    newtDrawRootText(strlen(packageVersion), 0,
		     _("(c) 1999-2003 Red Hat, Inc."));

    if (!getChoices(back, nisAvail, ldapAvail, kerberosAvail, smbAvail, cacheAvail, authInfo)) {
      /* cancelled */
      newtFinished();

      if (test) {
	fprintf(stderr, _("dialog was cancelled\n"));
	return 2;
      }

      return 1;
    }

    newtFinished();
  } /* kickstart */

  if (test) {
    authInfoPrint(authInfo);
    return 0;
  } else {
    if (authInfoWriteCache(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error recording caching setting"),
	      PACKAGE);
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteHesiod(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/hesiod.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteKerberos(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/krb5.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteLDAP(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/ldap.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteLibuser(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/libuser.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
    }
    if (authInfoWriteNIS(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/yp.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWriteSMB(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/pam_smb.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
    }
    if (authInfoWriteWinbind(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/samba/smb.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
    }
    if (authInfoWriteNSS(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/nsswitch.conf");
      fprintf(stderr, ": %s\n", strerror(errno));
    }
    if (authInfoWriteNetwork(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/sysconfig/network");
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (authInfoWritePAM(authInfo) == FALSE) {
      fprintf(stderr, _("%s: critical error writing %s/%s"),
	      PACKAGE, SYSCONFDIR, "/pam.d/" AUTH_PAM_SERVICE);
      fprintf(stderr, ": %s\n", strerror(errno));
      return 2;
    }
    if (winbindJoiner != NULL) {
      if (strchr(winbindJoiner, '%')) {
         const char *p;
         p = strchr(winbindJoiner, '%');
	 authInfo->joinUser = g_strndup(winbindJoiner, p - winbindJoiner);
	 authInfo->joinPassword = g_strdup(p + 1);
      } else {
	 authInfo->joinUser = g_strdup(winbindJoiner);
      }
      authInfoJoin(authInfo, TRUE);
    }
    authInfoPost(authInfo, nostart);
  }

  return 0;
}
