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

#define i18n(String) gettext((String))

/*
 * used throughout to denote different authentication methods.
 */
#define AUTH_PASSWORD 0
#define AUTH_NIS 1
#define AUTH_LDAP 2
#define AUTH_KERBEROS 3

static char *progName;

/*
 * used to hold information regarding different authentication
 * methods.  Add fields here if you add another type.  Even though
 * some of these fields are "common" across different authentication
 * types, we want to hold all the information so that if a user toggles
 * between the various types, the form can be pre-populated with the
 * information read from system configuration files.
 */
struct authInfoType {
  char *nisServer;
  char *nisDomain;
  
  char *ldapServer;
  char *ldapDomain;

  char *kerberosServer;
  char *kerberosDomain;

  char useShadow;
  char enableMD5;
};


/*
 * reads /etc/sysconfig/network, and determines the authorization domain
 * and type of authorization.
 * #'s denote comments. 
 */
static int readNetworkConfigFile(int *authType, struct authInfoType *authInfo)
{
  FILE *f;
  char *s, *s1;
  char buf[250];
  int line = 0;
  
  f = fopen("/etc/sysconfig/network", "r");
  if (!f) {
    if (errno == ENOENT) {
      return 0;
    }
    
    fprintf(stderr, i18n("%s: cannot open /etc/sysconfig/network: %s\n"),
	    progName, strerror(errno));
    return 1;
  }
  
  while ((s = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    line++;
    
    /* first, skip over any leading whitespace and blank lines */
    while (*s && isspace(*s)) 
      s++;
    if (!*s)
      continue;
    
    /* next, skip any lines that are comments */
    if (*s == '#')
      continue;
    
    /* cut trailing whitespace and \n from line */
    s1 = s + strlen(s) - 1;
    *s1 = '\0'; s1--;
    while (isspace(*s1))
      s1--;
    /* terminate the line */
    s1++;
    *s1 = '\0';
    s1--;
    
    /* look for the line we want */
    if (!strncmp("NISDOMAIN=", s, 10)) {
      s += 10;
      authInfo->nisDomain = strdup(s);
      *authType = AUTH_NIS;
    } else if (!strncmp("USELDAP=true", s, 12)) {
      s += 12;
      *authType = AUTH_LDAP;
    } else 
      s = NULL;
  }
  
  /* 
   * don't return an error if we don't find the line -- it may not
   * be there the first time they run the tool.
   */
  return 0;
}

/*
 * reads /etc/yp.conf, and determines the value of ypserver (if any).
 * #'s denote comments. 
 */
static int readYPConfigFile(char **nisServer)
{
  FILE *f;
  char *s, *s1;
  char buf[250];
  int line = 0;
  
  f = fopen("/etc/yp.conf", "r");
  if (!f) {
    if (errno == ENOENT) {
      return 0;
    }
    
    fprintf(stderr, i18n("%s: cannot open /etc/yp.conf: %s\n"),
	    progName, strerror(errno));
    return 1;
  }
  
  while ((s = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    line++;
    
    /* first, skip over any leading whitespace and blank lines */
    while (*s && isspace(*s)) 
      s++;
    if (!*s)
      continue;
    
    /* next, skip any lines that are comments */
    if (*s == '#')
      continue;
    
    /* cut trailing whitespace and \n from line */
    s1 = s + strlen(s) - 1;
    *s1 = '\0'; s1--;
    while (isspace(*s1))
      s1--;
    /* terminate the line */
    s1++;
    *s1 = '\0';
    s1--;
    
    /* look for the line we want */
    if (!strncmp("ypserver ", s, 9)) {
      s += 9;
      *nisServer = strdup(s);
    } else if (!strncmp("server ", s, 7)) {
      s += 7;
      *nisServer = strdup(s);
    } else
      s = NULL;
  }
  
  /* 
   * don't return an error if we don't find the line -- it may
   * be there the first time they run the tool.
   */
  return 0;
}

/*
 * read /etc/ldap.conf, and retrieve values for the ldapServer and ldapDomain.
 */
int readLdapConfigFile(char **ldapServer, char **ldapDomain)
{
  FILE *f;
  char *s, *s1;
  char buf[250];
  int line = 0;
  
  f = fopen("/etc/ldap.conf", "r");
  if (!f) {
    if (errno == ENOENT) {
      return 0;
    }
    
    fprintf(stderr, i18n("%s: cannot open /etc/ldap.conf: %s\n"),
	    progName, strerror(errno));
    return 1;
  }
  
  while ((s = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    line++;
    
    /* first, skip over any leading whitespace and blank lines */
    while (*s && isspace(*s)) 
      s++;
    if (!*s)
      continue;
    
    /* next, skip any lines that are comments */
    if (*s == '#')
      continue;
    
    /* cut trailing whitespace and \n from line */
    s1 = s + strlen(s) - 1;
    *s1 = '\0'; s1--;
    while (isspace(*s1))
      s1--;
    /* terminate the line */
    s1++;
    *s1 = '\0';
    s1--;
    
    /* look for the line we want */
    if (!strncmp("host ", s, 5)) {
      s += 5;
      *ldapServer = strdup(s);
    } else if (!strncmp("base ", s, 5)) {
      s += 5;
      *ldapDomain = strdup(s);
    } else
      s = NULL;
  }
  
  /* 
   * don't return an error if we don't find the line -- it may
   * be there the first time they run the tool.
   */
  return 0;
}


/*
 * the following two structures hold pointers to various components
 * and bits of information in the form, and a pointer to this info
 * is passed to the callback functions so they can make appropriate
 * modifications to the form/data.
 */

struct servercbInfo {
    char* state;
    newtComponent entry;
};

struct authcbInfo {
  char* bcastState;
  int *type;
  struct authInfoType *authInfo;

  newtComponent label1;
  newtComponent label2;
  newtComponent label3;
  newtComponent domEntry;
  newtComponent bcast;
  newtComponent serverEntry;
};


static void serverEntryToggle(newtComponent co, void * arg) 
{
  int sense = NEWT_FLAGS_SET;
  struct servercbInfo *cb = arg;
  
  if (*cb->state == ' ')
    sense = NEWT_FLAGS_RESET;
  
  newtEntrySetFlags(cb->entry, NEWT_FLAG_DISABLED, sense);
}


/*
 * The following callbacks are all activated when one of the
 * corresponding radio buttons are toggled.  They set up the
 * form so that it is in a sane state for that type of authentication,
 * possibly disabling some fields and changing some labels,
 * and pre-populating as much as possible with information that
 * was read from the system configuration files.
 */

static void passwordToggle(newtComponent co, void * arg) {
  struct authcbInfo *cb = arg;

  *(cb->type) = AUTH_PASSWORD;
  newtLabelSetText(cb->label1, "");
  newtLabelSetText(cb->label2, "");
  newtLabelSetText(cb->label3, "");

  newtEntrySet(cb->domEntry, "", 1);  
  newtEntrySet(cb->serverEntry, "", 1);

  newtEntrySetFlags(cb->domEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
  newtCheckboxSetFlags(cb->bcast, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
  newtCheckboxSetValue(cb->bcast, ' ');
  newtEntrySetFlags(cb->serverEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
}

static void nisToggle(newtComponent co, void * arg) 
{
  struct authcbInfo *cb = arg;
  
  *(cb->type) = AUTH_NIS;
  newtLabelSetText(cb->label1, i18n("    NIS Domain:"));
  newtLabelSetText(cb->label2, i18n("NIS Server:"));
  newtLabelSetText(cb->label3, i18n("         or use:"));

  newtEntrySet(cb->domEntry, (cb->authInfo->nisDomain ?
			      cb->authInfo->nisDomain : ""), 1);
  newtEntrySet(cb->serverEntry, (cb->authInfo->nisServer ?
				 cb->authInfo->nisServer : ""), 1);

  newtEntrySetFlags(cb->domEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
  newtCheckboxSetFlags(cb->bcast, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
  if (*cb->bcastState == ' ')
    newtEntrySetFlags(cb->serverEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
}

static void ldapToggle(newtComponent co, void * arg) 
{
  struct authcbInfo *cb = arg;
  
  *(cb->type) = AUTH_LDAP;
  newtLabelSetText(cb->label1, i18n("   LDAP Domain:"));
  newtLabelSetText(cb->label2, "");
  newtLabelSetText(cb->label3, i18n("    LDAP Server:"));

  newtEntrySet(cb->domEntry, (cb->authInfo->ldapDomain ?
			      cb->authInfo->ldapDomain : ""), 1);
  newtEntrySet(cb->serverEntry, (cb->authInfo->ldapServer ?
				 cb->authInfo->ldapServer : ""), 1);
  
  newtEntrySetFlags(cb->domEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
  newtCheckboxSetFlags(cb->bcast, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
  newtCheckboxSetValue(cb->bcast, ' ');
  newtEntrySetFlags(cb->serverEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
}

static void kerberosToggle(newtComponent co, void * arg) 
{
  struct authcbInfo *cb = arg;
  
  *(cb->type) = AUTH_KERBEROS;
  newtLabelSetText(cb->label1, i18n("Kerberos Realm:"));
  newtLabelSetText(cb->label2, "");
  newtLabelSetText(cb->label3, i18n("Kerberos Server:"));

  newtEntrySet(cb->domEntry, (cb->authInfo->kerberosDomain ?
			      cb->authInfo->kerberosDomain : ""), 1);
  newtEntrySet(cb->serverEntry, (cb->authInfo->kerberosServer ?
				 cb->authInfo->kerberosServer : ""), 1);
  
  newtEntrySetFlags(cb->domEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
  newtCheckboxSetFlags(cb->bcast, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
  newtCheckboxSetValue(cb->bcast, ' ');
  newtEntrySetFlags(cb->serverEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
}

/*
 * small callback to disallow spaces in an entry field.
 */
int entryFilter(newtComponent entry, void * data, int ch, int cursor)
{
    if (ch == ' ')
	return 0;
    return ch;
}

/*
 * draw the main window for authconfig.  Displays choices about
 * using various authentication methods.  return results by reference.
 */
int getChoices(int useBack, int nisAvail, int ldapAvail, int kerberosAvail,
	       int *authType, struct authInfoType *authInfo,  
	       char *enableNisServer)
{
  newtComponent mainForm;
  newtGrid mainGrid, subGrid1, subGrid2, buttons;
  newtComponent authDomainLabel, authDomainEntry;
  newtComponent bcastCheckBox, authServerLabel,  authServerEntry;
  newtComponent shadowCheckBox, MD5CheckBox;
  newtComponent okButton, cancelButton;
  newtComponent answer;
  newtComponent authLabel;
  newtComponent passwordRadio, nisRadio = 0;
  newtComponent ldapRadio = 0, kerbRadio = 0, prevRadio = 0;
  newtComponent tmpLabel;
  char *newAuthDomain = NULL, *newAuthServer = NULL;
  char newUseShadow, newEnableMD5, newEnableBroadCast;
  struct servercbInfo servercb;
  struct authcbInfo authcb;
  int done = 0;
  int length;
  char dummyStr[80];

  /* create the main form and window */
  mainForm = newtForm(NULL, NULL, 0);

  /*
   * what kind of authentication?
   */
  authLabel = newtLabel(-1, -1, i18n("Authentication Type:"));
  passwordRadio = newtRadiobutton(-1, -1, i18n("Password File"), 
			      *authType == AUTH_PASSWORD, 0);
  prevRadio = passwordRadio;

  if (nisAvail) {
    nisRadio = newtRadiobutton(-1, -1, i18n("NIS"), 
			       *authType == AUTH_NIS, prevRadio);
    prevRadio = nisRadio;
  }

  if (ldapAvail) {
    ldapRadio = newtRadiobutton(-1, -1, i18n("LDAP"), 
				*authType == AUTH_LDAP, prevRadio);
    prevRadio = ldapRadio;
  }

  if (kerberosAvail) {
    kerbRadio = newtRadiobutton(-1, -1, i18n("Kerberos"), 
				*authType == AUTH_KERBEROS, prevRadio);
    prevRadio = kerbRadio;
  }

  /*
   * authentication server stuff.
   */


  /* 
   * find length of longest string. Looks useless when strings
   * are right-padded as below, but will be necessary for xlations
   * if they don't pad.
   */
  length =   strlen(i18n("         or use:"));
  if (strlen(i18n("    LDAP Server:")) > length)
    length = strlen(i18n("    LDAP Server:"));
  if (strlen(i18n("Kerberos Server:")) > length)
    length = strlen(i18n("Kerberos Server:"));

  if (length > 80)
    abort();

  memset(dummyStr, ' ', 80);
  dummyStr[length] = '\0';

  authServerLabel = newtLabel(-1, -1, i18n("NIS Server:"));
  bcastCheckBox = newtCheckbox(-1, -1, i18n("Request via broadcast"),
	       (*enableNisServer == '*' || !nisAvail) ? ' ' : '*',
			       0, &newEnableBroadCast);
  
  tmpLabel = newtLabel(-1, -1, dummyStr);

  authServerEntry = newtEntry(-1, -1, "", 25, &newAuthServer,
			     NEWT_FLAG_SCROLL);
  newtEntrySetFilter(authServerEntry, entryFilter, NULL);
  
  if (*enableNisServer == ' ')
      newtEntrySetFlags(authServerEntry, NEWT_FLAG_DISABLED,
			NEWT_FLAGS_SET);
  
  servercb.state = &newEnableBroadCast;
  servercb.entry = authServerEntry;
  newtComponentAddCallback(bcastCheckBox, serverEntryToggle,
			   &servercb);

  /* 
   * find length of longest string. Looks useless when strings
   * are right-padded as below, but will be necessary for xlations
   * if they don't pad.
   */
  length =   strlen(i18n("    NIS Domain:"));
  if (strlen(i18n("   LDAP Domain:")) > length)
    length = strlen(i18n("   LDAP Domain:"));
  if (strlen(i18n("Kerberos Realm:")) > length)
    length = strlen(i18n("Kerberos Realm:"));

  if (length > 80)
    abort();

  memset(dummyStr, ' ', 80);
  dummyStr[length] = '\0';

  authDomainLabel = newtLabel(-1, -1, dummyStr);
  authDomainEntry = newtEntry(-1, -1, "", 25, &newAuthDomain, 
		       NEWT_FLAG_SCROLL);
  newtEntrySetFilter(authDomainEntry, entryFilter, NULL);
  
  authcb.type = authType;
  authcb.authInfo = authInfo;
  authcb.label1 = authDomainLabel;
  authcb.label2 = authServerLabel;
  authcb.label3 = tmpLabel;
  authcb.bcastState = &newEnableBroadCast;
  authcb.domEntry = authDomainEntry;
  authcb.bcast = bcastCheckBox;
  authcb.serverEntry = authServerEntry;
    
  serverEntryToggle(bcastCheckBox, &servercb);

  if (newtRadioGetCurrent(prevRadio) == NULL) {
    fprintf(stderr,"warning! no buttons are default!");
    fprintf(stderr,"authType: %d",*authType);
  }
  if (newtRadioGetCurrent(prevRadio) == passwordRadio)
    passwordToggle(nisRadio, &authcb);
  else if (newtRadioGetCurrent(prevRadio) == nisRadio)
    nisToggle(nisRadio, &authcb);
  else if (newtRadioGetCurrent(prevRadio) == ldapRadio)
    ldapToggle(ldapRadio, &authcb);  
  else if (newtRadioGetCurrent(prevRadio) == kerbRadio)
    kerberosToggle(kerbRadio, &authcb);
  
  /*  if (!nisAvail) {
      newtEntrySetFlags(authServerEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
      newtCheckboxSetFlags(bcastCheckBox, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
      newtEntrySetFlags(authDomainEntry, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
      }*/
      
  /* Shadow Stuff */
  shadowCheckBox = newtCheckbox(-1, -1, i18n("Use Shadow Passwords"),
				0, 0, &newUseShadow);
  MD5CheckBox = newtCheckbox(-1, -1, i18n("Enable MD5 Passwords"),
			     0, 0, &newEnableMD5);

  newtCheckboxSetValue(shadowCheckBox, authInfo->useShadow);

  newtCheckboxSetValue(MD5CheckBox, authInfo->enableMD5);

  buttons =  newtButtonBar(i18n("Ok"), &okButton,
			   useBack ? i18n("Back") : i18n("Cancel"),
			   &cancelButton,
			   NULL);

  mainGrid = newtCreateGrid(1, 6);

  /* Row 2 of main grid */
  
  /* Create the subgrid for auth type */
  subGrid1 = newtCreateGrid(4, 6);

  newtGridSetField(subGrid1, 0, 0, NEWT_GRID_COMPONENT, authLabel,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);

  /* Radio Buttons */
  newtGridSetField(subGrid1, 0, 1, NEWT_GRID_COMPONENT, passwordRadio,
		   0, 0, 1, 0, NEWT_ANCHOR_LEFT, 0);
  if (nisAvail)
    newtGridSetField(subGrid1, 1, 1, NEWT_GRID_COMPONENT, nisRadio,
		     1, 0, 1, 0, NEWT_ANCHOR_LEFT, 0);
  if (ldapAvail)
    newtGridSetField(subGrid1, 2, 1, NEWT_GRID_COMPONENT, ldapRadio,
		     1, 0, 1, 0, NEWT_ANCHOR_LEFT, 0);
  if (kerberosAvail)
    newtGridSetField(subGrid1, 3, 1, NEWT_GRID_COMPONENT, kerbRadio,
		     1, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);

  /* add the subgrid to the main grid */
  newtGridSetField(mainGrid, 0, 1, NEWT_GRID_SUBGRID, subGrid1, 
		   0, 1, 0, 1, 0, 0);


  /* Create the subgrid for nis info */
  subGrid2 = newtCreateGrid(2, 4);

  newtGridSetField(subGrid2, 0, 1, NEWT_GRID_COMPONENT, authDomainLabel,
		   1, 0, 1, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(subGrid2, 1, 1, NEWT_GRID_COMPONENT, authDomainEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  newtGridSetField(subGrid2, 0, 2, NEWT_GRID_COMPONENT, authServerLabel,
		   1, 0, 1, 0, NEWT_ANCHOR_RIGHT, 0);
  
  newtGridSetField(subGrid2, 1, 2, NEWT_GRID_COMPONENT, bcastCheckBox,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);

  newtGridSetField(subGrid2, 0, 3, NEWT_GRID_COMPONENT, tmpLabel, 
		   0, 0, 1, 0, NEWT_ANCHOR_RIGHT, 0);
  newtGridSetField(subGrid2, 1, 3, NEWT_GRID_COMPONENT, authServerEntry,
		   0, 0, 0, 0, NEWT_ANCHOR_LEFT, 0);
  
  /* add the subgrid to the main grid */
  newtGridSetField(mainGrid, 0, 2, NEWT_GRID_SUBGRID, subGrid2, 
		   0, 1, 0, 1, 0, NEWT_GRID_FLAG_GROWX);
  
  /* Row 4... and so on */
  
  newtGridSetField(mainGrid, 0, 3, NEWT_GRID_COMPONENT, shadowCheckBox, 
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);

  newtGridSetField(mainGrid, 0, 4, NEWT_GRID_COMPONENT, MD5CheckBox, 
		   0, 0, 0, 1, NEWT_ANCHOR_LEFT, 0);
    
  newtGridSetField(mainGrid, 0, 5, NEWT_GRID_SUBGRID, buttons, 
		   0, 0, 0, 0, 0, NEWT_GRID_FLAG_GROWX);

  newtGridAddComponentsToForm(mainGrid, mainForm, 1);
  
  newtGridWrappedWindow(mainGrid, i18n("Authentication Configuration"));

  newtComponentAddCallback(passwordRadio, passwordToggle,
			   &authcb);
  if (nisAvail)
    newtComponentAddCallback(nisRadio, nisToggle,
			     &authcb);
  if (ldapAvail)
    newtComponentAddCallback(ldapRadio, ldapToggle,
			     &authcb);
  if (kerberosAvail)
    newtComponentAddCallback(kerbRadio, kerberosToggle,
			     &authcb);

  /*
   * run the form and process results until satisfied.
   */
  do {
      answer = newtRunForm(mainForm);
  
      if (answer == cancelButton) {
	  newtPopWindow();
	  return 1;
      } else {
	/* process form values */
	if (nisAvail && *authType == AUTH_NIS) {
	  *enableNisServer = newEnableBroadCast == '*' ? ' ' : '*';
	  if (*enableNisServer == '*' && !strcmp(newAuthServer, "")) {
	    newtWinMessage(i18n("Error"), i18n("Ok"),
			   i18n("You must enter a NIS server or "
				"request via broadcast."));
	    done = 0;
	    continue;
	  }
	}
	
	if (!strcmp(newAuthDomain, "") && *authType != AUTH_PASSWORD) {
	  newtWinMessage(i18n("Error"), i18n("Ok"),
			 i18n("You must enter an authentication domain."));
	  done = 0;
	  continue;
	}

	/*
	 * error checking done, insert new values
	 */
	switch (*authType) {
	case AUTH_PASSWORD:
	  break;
	case AUTH_NIS:
	  authInfo->nisDomain = newAuthDomain;
	  authInfo->nisServer = newAuthServer;
	  break;
	case AUTH_LDAP:
	  authInfo->ldapDomain = newAuthDomain;
	  authInfo->ldapServer = newAuthServer;
	  break;
	case AUTH_KERBEROS:
	  authInfo->kerberosDomain = newAuthDomain;
	  authInfo->kerberosServer = newAuthServer;
	  break;
	}
      }
      
      authInfo->useShadow = newUseShadow;
      authInfo->enableMD5 = newEnableMD5;

      done = 1;

  } while (!done);
  
  return 0;
}

/*
 * this function will rewrite /etc/sysconfig/network to have the new
 * value for NISDOMAIN or USELDAP.
 */
int rewriteNetworkConfigFile(int authType, struct authInfoType *authInfo)
{
  FILE *f, *f1;
  char *s, *s2;
  char buf[250];
  int line = 0;
  int found = 0;

  f = fopen("/etc/sysconfig/network", "r");
  if (!f) {
    fprintf(stderr, i18n("%s: cannot open /etc/sysconfig/network: %s\n"),
	    progName, strerror(errno));
    return 1;
  }

  f1 = fopen("/etc/sysconfig/network-", "w");
  if (!f) {
    fprintf(stderr, i18n("%s: cannot open /etc/sysconfig/network- for writing: %s\n"),
	    progName, strerror(errno));
    return 1;
  }

  while ((s2 = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    s = s2;
    line++;

    /* first, skip over any leading whitespace and blank lines */
    while (*s && isspace(*s)) 
      s++;
    if (!*s) {
      fprintf(f1, s2);
      continue;
    }

    /* next, skip any lines that are comments */
    if (*s == '#') {
      fprintf(f1, s2);
      continue;
    }

    /* look for the lines we want */
    if (!strncmp("NISDOMAIN=", s, 10)) {
      if (authType == AUTH_NIS) {
	fprintf(f1,"NISDOMAIN=%s\n",authInfo->nisDomain);
	found = 1;
      }
    } else if (!strncmp("USELDAP=", s, 8)) {
      if (authType == AUTH_LDAP) {
	fprintf(f1,"USELDAP=true\n");
	found = 1;
      }
    } else {
      fprintf(f1, "%s",s2);
    }
  }

  /* 
   * here, we write the value if we haven't done so already (it is a new
   * value for the config file...)
   */
  if (!found) {
    switch(authType) {
      case AUTH_PASSWORD:
	break;
    case AUTH_NIS:
      fprintf(f1, "NISDOMAIN=%s\n",authInfo->nisDomain);
      break;
    case AUTH_LDAP:
      fprintf(f1, "USELDAP=true\n");
      break;
    case AUTH_KERBEROS:
      break;
    }
  }

  fclose(f);
  fclose(f1);

  /* rename the temporary file */
  unlink("/etc/sysconfig/network");
  rename("/etc/sysconfig/network-", "/etc/sysconfig/network");

  /* 
   * don't return an error if we don't find the line -- it may not
   * be there the first time they run the tool.
   */
  return 0;

}

/*
 * this function will rewrite /etc/yp.conf to have the new
 * value for ypserver.  If enableNisServer == ' ', removes this field.
 */
int rewriteYPConfigFile(int enableNis, char enableNisServer,
			char *nisServer, char *nisDomain)
{
  FILE *f, *f1;
  char *s, *s2;
  char buf[250];
  int line = 0;
  int ypserverFound = 0, serverFound = 0, domainFound = 0;

  f = fopen("/etc/yp.conf", "r");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/yp.conf: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  f1 = fopen("/etc/yp.conf-", "w");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/yp.conf- for writing: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  while ((s2 = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
      s = s2;
      line++;
      
      /* first, skip over any leading whitespace and blank lines */
      while (*s && isspace(*s)) 
	  s++;
      if (!*s) {
	  fputs(s2, f1);
	  continue;
      }
      
      /* next, skip any lines that are comments */
      if (*s == '#') {
	  fputs(s2, f1);
	  continue;
      }

      if (!enableNis)
	  continue;
      
      /* look for the line we want */
      if (!strncmp("ypserver ", s, 9)) {
	  /*
	   * OK, now instead of this line we want to write the new line,
	   * if enableNisServer is '*'. 
	   */
	  if (enableNisServer == '*') {
	      fprintf(f1,"ypserver %s\n",nisServer);
	      ypserverFound = 1;
	  }
      } else if (!strncmp("server ", s, 7)) {
	  if (enableNisServer == '*') {
	      fprintf(f1, "server %s\n",nisServer);
	      serverFound = 1;
	  }
      } else if (!strncmp("domain ", s, 7)) {
	  if (enableNisServer == '*') {
	      fprintf(f1, "domain %s\n",nisDomain);
	      domainFound = 1;
	  }
      } else {
	  fputs(s2, f1);
      }
  }
  
  /* 
   * here, we write the value if we haven't done so already (it is a new
   * value for the config file...)
   */

  if (enableNis) {
      if (!serverFound && enableNisServer == '*')
	  fprintf(f1, "server %s\n",nisServer);
      if (!ypserverFound && enableNisServer == '*')
	  fprintf(f1, "ypserver %s\n",nisServer);
      if (!domainFound)
	  fprintf(f1, "domain %s %s\n",nisDomain,
		  enableNisServer == ' ' ? "broadcast" : "");
  }
  
  fclose(f);
  fclose(f1);
  
  /* rename the temporary file */
  unlink("/etc/yp.conf");
  rename("/etc/yp.conf-", "/etc/yp.conf");

  /* 
   * don't return an error if we don't find the line -- it may not
   * be there the first time they run the tool.
   */
  return 0;

}

/*
 * this function will rewrite /etc/ldap.conf to have the new
 * values for LDAP.
 */
int rewriteLdapConfigFile(int enableLdap, char *ldapServer, 
			  char *ldapDomain, char enableMD5)
{
  FILE *f, *f1;
  char *s, *s2;
  char buf[250];
  int line = 0;
  int serverFound = 0, domainFound = 0;
  int cryptFound = 0;

  f = fopen("/etc/ldap.conf", "r");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/ldap.conf: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  f1 = fopen("/etc/ldap.conf-", "w");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/ldap.conf- for writing: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  while ((s2 = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    s = s2;
    line++;
    
    /* first, skip over any leading whitespace and blank lines */
    while (*s && isspace(*s)) 
      s++;
    if (!*s) {
      fputs(s2, f1);
      continue;
    }
    
    /* next, skip any lines that are comments */
    if (*s == '#') {
      fputs(s2, f1);
      continue;
    }
    
    /* look for the line we want */
    if (!strncmp("host ", s, 5) && enableLdap) {
      fprintf(f1, "host %s\n",ldapServer);
      serverFound = 1;
    } else if (!strncmp("base ", s, 5) && enableLdap) {
      fprintf(f1, "base %s\n",ldapDomain);
      domainFound = 1;
    } else if (!strncmp("pam_crypt local", s, 15)) {
      cryptFound = 1;
    } else {
      fputs(s2, f1);
    }
  }
  
  /* 
   * here, we write the value if we haven't done so already (it is a new
   * value for the config file...)
   */
  
  if (enableLdap) {
    if (!serverFound)
      fprintf(f1, "host %s\n",ldapServer);
    if (!domainFound)
      fprintf(f1, "bind %s\n",ldapDomain);
    if (!cryptFound)
      fprintf(f1, "pam_crypt local\n");
  }
  
  fclose(f);
  fclose(f1);
  
  /* rename the temporary file */
  unlink("/etc/ldap.conf");
  rename("/etc/ldap.conf-", "/etc/ldap.conf");

  /* 
   * don't return an error if we don't find the line -- it may not
   * be there the first time they run the tool.
   */
  return 0;

}

/*
 * edit /etc/nsswitch.conf
 */
int rewriteNsswitchFile(int authType, struct authInfoType *authInfo)
{
  FILE *f, *f1;
  char *s, *s2;
  char *p, *p2;
  char buf[250];
  int line = 0;

  f = fopen("/etc/nsswitch.conf", "r");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/nsswitch.conf: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  f1 = fopen("/etc/nsswitch.conf-", "w");
  if (!f) {
      fprintf(stderr, i18n("%s: cannot open /etc/nsswitch.conf- for writing: %s\n"),
	      progName, strerror(errno));
      return 1;
  }
  
  while ((s2 = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
      s = s2;
      line++;
      
      /* first, skip over any leading whitespace and blank lines */
      while (*s && isspace(*s)) 
	  s++;
      if (!*s) {
	  fputs(s2, f1);
	  continue;
      }
      
      /* next, skip any lines that are comments */
      if (*s == '#') {
	  fputs(s2, f1);
	  continue;
      }

      /* look for the line we want */
      if (!strncmp("passwd:", s, 7)) {
	s += 7;
	// skip over intermediate whitespace
	while (*s && isspace(*s))
	  s++;
	/* replace newline with \0. */
	p = strchr(s, '\n');
	if (p != 0)
	  *p = '\0';

	p = strstr(s, "ldap");
	if (p != 0) {
	  p2 = p + 5; /* skip over ldap text and a space */
	  if (*p2 == '\0')
	    *p = '\0';
	  else
	    memmove(p, p2, strlen(p2) + 1); /* include \0 */
	}

	fprintf(f1, "passwd:     %s%s\n",(authType == AUTH_LDAP ?
					  "ldap " : ""), s);
      } else if (!strncmp("group:", s, 6)) {
	s += 6;
	// skip over intermediate whitespace
	while (*s && isspace(*s))
	  s++;
	/* replace newline with \0. */
	p = strchr(s, '\n');
	if (p != 0)
	  *p = '\0';

	p = strstr(s, "ldap");
	if (p != 0) {
	  p2 = p + 5; /* skip over ldap text and a space */
	  if (*p2 == '\0')
	    *p = '\0';
	  else
	    memmove(p, p2, strlen(p2) + 1); /* include \0 */
	  sleep (5);
	}

	fprintf(f1, "group:      %s%s\n",(authType == AUTH_LDAP ?
					  "ldap " : ""), s);
      } else if (!strncmp("hosts:", s, 6)) {
	s += 6;
	// skip over intermediate whitespace
	while (*s && isspace(*s))
	  s++;
	/* replace newline with \0. */
	p = strchr(s, '\n');
	if (p != 0)
	  *p = '\0';

	p = strstr(s, "ldap");
	if (p != 0) {
	  p2 = p + 5; /* skip over ldap text and a space */
	  if (*p2 == '\0')
	    *p = '\0';
	  else
	    memmove(p, p2, strlen(p2) + 1); /* include \0 */
	}

	fprintf(f1, "hosts:      %s%s\n",s, (authType == AUTH_LDAP ?
					     " ldap" : ""));
      } else {
	fputs(s2, f1);
      }
  }
  
  fclose(f);
  fclose(f1);
  
  /* rename the temporary file */
  unlink("/etc/nsswitch.conf");
  rename("/etc/nsswitch.conf-", "/etc/nsswitch.conf");

  /* 
   * don't return an error if we don't find the line -- it may not
   * be there the first time they run the tool.
   */
  return 0;

}

int toggleNisService(int enableNis, char *nisDomain, int nostart)
{
  char domainStr[200];
  if (enableNis) { 
      sprintf(domainStr,"/bin/domainname %s", nisDomain);
      system(domainStr);
    if (!nostart) 
      system("/etc/rc.d/init.d/ypbind restart");
    system("/sbin/chkconfig --level 345 ypbind on");
  }  else {
    system("/bin/domainname \"(none)\"");
    if (!nostart)
      system("/etc/rc.d/init.d/ypbind stop");
    system("/sbin/chkconfig --del ypbind");
  }

  return 0;
}

int toggleShadowPam(int enable, int md5)
{
  char *filenames[] = { "login", "rlogin", "passwd", 0 };    
  FILE *f, *f1;
  char curFileName[80], curTmpFileName[80], buf[250];
  char *s, *s1;
  char *shadowFound, *md5Found;
  int i;
  
  for (i = 0; filenames[i]; i++) {
    sprintf(curFileName,"/etc/pam.d/%s",filenames[i]);
    f = fopen(curFileName, "r");
    if (!f)
      continue;

    sprintf(curTmpFileName,"%s-",curFileName);
    f1 = fopen(curTmpFileName, "w");
    while ((s = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
      /* chop \n off end of line */
      if (s[strlen(s)-1] == '\n')
	s[strlen(s)-1] = '\0';
      
      /* look for "password" at the beginning of the line, amd pam_pwdb.so somewhere in line */
      if (!strncmp(s, "password", 8) && (strstr(s, "pam_pwdb.so") != NULL)) {
	/* set these flags to what we find in the string */
	shadowFound = strstr(s,"shadow");
	
	s1 = strdup(s);
	/* chop out shadow and md5.  We'll add it back later if needed */
	if (shadowFound != NULL) {
	  shadowFound--;
	  *shadowFound = '\0';
	  strcpy(s1, s);
	  shadowFound += 7; /* one character after "shadow" */
	  s1 = (char *) realloc(s1, sizeof(char *) * (strlen(s1) + strlen(shadowFound) + 1));
	  strcat(s1, shadowFound);
	}

	s = s1;
	s1 = strdup(s);
	md5Found = strstr(s,"md5");
	if (md5Found != NULL) {
	  md5Found--;
	  *md5Found = '\0';
	  strcpy(s1, s);
	  md5Found += 4; /* one character after "md5" */
	  s1 = (char *) realloc(s1, sizeof(char *) * (strlen(s1) + strlen(md5Found) + 1));
	  strcat(s1, md5Found);
	}
	s = s1;

	if (md5) {
	  s = realloc(s, sizeof(char *) * (strlen(s) + 5));
	  strcat(s, " md5");
	}
	if (enable) {
	  s = realloc(s, sizeof(char *) * (strlen(s) + 8));
	  strcat(s, " shadow");
	}
      } 
      fprintf(f1,"%s\n",s);
    }

    fclose(f);
    fclose(f1);
    unlink(curFileName);
    rename(curTmpFileName, curFileName);
  }

  return 0;
}

int checkEnableMD5(struct authInfoType *authInfo)
{
  char *filename = "/etc/pam.d/passwd";
  char buf[250];
  FILE *f;
  char *s;

  f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr,i18n("%s: error opening %s\n"),progName, filename);
    return 1;
  }
   
  while ((s = fgets(buf, sizeof(buf) - 1, f)) != NULL) {
    /* look for "password" at the beginning of the line, amd pam_pwdb.so somewhere in line */
    if (!strncmp(s, "password", 8) && (strstr(s, "pam_pwdb.so") != NULL)) {
      /* set these flags to what we find in the string */
      if (strstr(s,"md5") != NULL)
	authInfo->enableMD5 = '*';
    }
  }
  
  fclose(f);
  return 0;
}

int doShadowStuff(struct authInfoType *authInfo)
{
  /* first, toggle the shadow service for all required pam modules. */
  if (toggleShadowPam((authInfo->useShadow == '*' ? 1 : 0),
		      (authInfo->enableMD5 == '*' ? 1 : 0)))
    return 1;
  
  /* now, do file manipulation on the password files themselves. */
  if (authInfo->useShadow == '*') {
    system("/usr/sbin/pwconv");
    system("/usr/sbin/grpconv");
  } else {
    system("/usr/sbin/pwunconv");
    system("/usr/sbin/grpunconv");
  }
  return 0;
}

void usage(void) {
    fprintf(stderr, i18n("Usage: %s [options]\n\n"
			 "     --nostart            do not start/stop yp\n"
			 "     --enablenis          enable nis by default\n"
			 "     --nisdomain <domain> default NIS domain\n"
			 "     --nisserver <server> default NIS server\n"
			 "     --useshadow          use shadow passwords\n"
			 "     --enablemd5          enable MD5 passwords\n"
			 "     --kickstart          don't display user interface\n"
			 "     --help               show this screen\n"),
	    progName);

    exit(0);
}

int main(int argc, const char **argv) {
  int rc;
  struct stat sb;

  struct authInfoType authInfo;

  char *authArg;
  int authType = AUTH_PASSWORD;
  char enableNisServer = ' ';

  int back = 0, test = 0, nostart = 0;
  int kickstart = 0;
  int enablenis = 0, useshadow = 0, enablemd5 = 0;
  int help = 0;
  int nisAvail = 0;
  int ldapAvail = 0;
  int kerberosAvail = 0;
  poptContext optCon;
  const struct poptOption options[] = {
    { "back", '\0', 0, &back, 0, NULL, NULL},
    { "test", '\0', 0, &test, 0, NULL, NULL},
    { "nostart", '\0', 0, &nostart, 0, NULL, NULL},
    { "kickstart", '\0', 0, &kickstart, 0, NULL, NULL},
    { "authtype", '\0', 1, &authArg, 0, "authorization type", 
      "password, nis, ldap, or kerberos" },
    { "enablenis", '\0', 0, &enablenis, 0, NULL, NULL},
    { "nisdomain", '\0', POPT_ARG_STRING, &authInfo.nisDomain, 0, NULL, NULL},
    { "nisserver", '\0', POPT_ARG_STRING, &authInfo.nisServer, 0, NULL, NULL},
    { "useshadow", '\0', 0, &useshadow, 0, NULL, NULL},
    { "enablemd5", '\0', 0, &enablemd5, 0, NULL, NULL},
    { "help", 'h', 0, &help, 0, NULL, NULL},
    { 0, 0, 0, 0, 0, 0 },
  };

  authInfo.nisDomain = NULL; authInfo.nisServer = NULL;
  authInfo.ldapDomain = NULL; authInfo.ldapServer = NULL;
  authInfo.kerberosDomain = NULL; authInfo.kerberosServer = NULL;
  authInfo.useShadow = ' ';
  authInfo.enableMD5 = ' ' ;

  progName = basename((char *)argv[0]);

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

  /* process other arguments */
  if (authArg) {
    if (strcasecmp(authArg, "password") != -1)
      authType = AUTH_PASSWORD;
    else if (strcasecmp(authArg, "nis") != -1)
      authType = AUTH_NIS;
    else if (strcasecmp(authArg, "ldap") != -1)
      authType = AUTH_LDAP;
    else if (strcasecmp(authArg, "kerberos") != -1)
      authType = AUTH_KERBEROS;
    else {
      fprintf(stderr, i18n("%s: unknown authorization type %s\n"),
	      progName, authArg);
      return 2;
    }
  }

  if (enablenis)
    authType = AUTH_NIS;

  if (useshadow)
    authInfo.useShadow = '*';
  if (enablemd5)
    authInfo.enableMD5 = '*';

  /* read the values from the config file */
  if (readNetworkConfigFile(&authType, &authInfo)) {
    fprintf(stderr, i18n("%s: critical error reading /etc/sysconfig/network"),
	    progName);
    return 2;
  }

  /* check for NIS */
  if (!access("/etc/yp.conf", R_OK)) {
    /* read the values from yp.conf */
    if (readYPConfigFile(&authInfo.nisServer)) {
      fprintf(stderr, i18n("%s: critical error reading /etc/yp.conf"),
	      progName);
      return 2;
    }
    nisAvail = 1;
  } else
    nisAvail = 0;

  if (!authInfo.nisServer)
    authInfo.nisServer = "";
  else
    enableNisServer = '*';

  /* check for LDAP */
  if (!access("/etc/ldap.conf", R_OK) && 
      !access("/usr/lib/nss_ldap.so", R_OK)) {
    /* LDAP available */
    if (readLdapConfigFile(&authInfo.ldapServer, 
			   &authInfo.ldapDomain)) {
      fprintf(stderr, i18n("%s: critical error reading /etc/ldap.conf"),
	      progName);
      return 2;
    }
    ldapAvail = 1;
  } else
    ldapAvail = 0;

  if (!stat("/etc/shadow", &sb))
    authInfo.useShadow = '*';

  if (checkEnableMD5(&authInfo)) {
    fprintf(stderr, i18n("%s: critical error reading /etc/pam.d/passwd\n"),
	    progName);
    return 2;
  }

  if (!kickstart) {
    newtInit();
    newtCls();
    
    newtPushHelpLine(i18n(" <Tab>/<Alt-Tab> between elements   |   <Space> selects   |  <F12> next screen"));
    newtDrawRootText(0, 0, "authconfig " VERSION " - (c) 1999, 2000 Red Hat, Inc.");
    
    if (getChoices(back, nisAvail, ldapAvail, kerberosAvail,
		   &authType, &authInfo, 
		   &enableNisServer)) {
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
    fprintf(stderr,i18n("authentication type selected: "));
    switch(authType) {
    case AUTH_PASSWORD:
      fprintf(stderr,"password\n");
      break;
    case AUTH_NIS:
      fprintf(stderr,"NIS\n");
      fprintf(stderr, "return values: domain: %s, server: %s, ",
	      authInfo.nisDomain, authInfo.nisServer);
      break;
    case AUTH_LDAP:
      fprintf(stderr,"LDAP\n");
      fprintf(stderr, "return values: domain: %s, server: %s, ",
	      authInfo.ldapDomain, authInfo.ldapServer);
      break;
    case AUTH_KERBEROS:
      fprintf(stderr,"Kerberos\n");
      fprintf(stderr, "return values: domain: %s, server: %s, ",
	      authInfo.kerberosDomain, authInfo.kerberosServer);
      break;
    }

    fprintf(stderr, "shadow: %c, md5: %c\n",
	    authInfo.useShadow, authInfo.enableMD5);
    return 0;

  }
  
  /* here, we write the config files / activate changes. */
  if (rewriteNetworkConfigFile(authType, &authInfo)) {
    fprintf(stderr, i18n("%s: critical error writing /etc/sysconfig/network\n"),
	    progName);
    return 2;
  }
  
  if (nisAvail) {
    if (rewriteYPConfigFile((authType == AUTH_NIS), enableNisServer,
			    authInfo.nisServer, authInfo.nisDomain)) {
      fprintf(stderr, i18n("%s: critical error writing /etc/yp.conf\n"),
	      progName);
      return 2;
    }

    if (toggleNisService((authType == AUTH_NIS), 
			 authInfo.nisDomain, nostart)) {
      fprintf(stderr, i18n("%s: critical error turning on NIS service\n"),
	      progName);
      return 2;
    }
  }
      
  /*
   * activate / deactive LDAP.
   */
  if (ldapAvail) {
    if (rewriteLdapConfigFile((authType == AUTH_LDAP), authInfo.ldapServer,
			      authInfo.ldapDomain, authInfo.enableMD5)) {
      fprintf(stderr, i18n("%s: critical error writing /etc/ldap.conf\n"),
	      progName);
      return 2;
    }
  }

  /*
   * edit the name service switch file.
   */
  if (rewriteNsswitchFile(authType, &authInfo)) {
    fprintf(stderr, i18n("%s: critical error writing /etc/nsswitch.conf\n"),
	    progName);
    return 2;
  }

  /*
   * do shadow conversion / unconversion on local passwd file
   */
  if (doShadowStuff(&authInfo)) {
    fprintf(stderr, i18n("%s: critical error with shadow password manipulation\n"),
	    progName);
    return 2;
  }

  return 0;
}
