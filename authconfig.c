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

static char *progName;

/*
 * reads /etc/sysconfig/network, and determines the value of NISDOMAIN.
 * #'s denote comments. 
 */
static int readNetworkConfigFile(char **nisDomain)
{
  FILE *f;
  char *s, *s1;
  char buf[250];
  int line = 0;
  
  f = fopen("/etc/sysconfig/network", "r");
  if (!f) {
    if (errno = ENOENT) {
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
      *nisDomain = strdup(s);
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
    if (errno = ENOENT) {
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
 * draw the main window for authconfig.  Displays choices about
 * using NIS and shadow passwords.  return results by reference.
 */
int getChoices(int useBack, char *enableNis, char **nisDomain,  
	       char *enableNisServer, char **nisServer,
	       char *enableShadow, char *useMD5)
{
  newtComponent mainForm;
  /*  newtGrid mainGrid;*/
  newtComponent nisCheckBox, nisLabel, nisEntry;
  newtComponent serverRadios[2], nisServerLabel,  nisServerEntry;
  newtComponent shadowCheckBox, MD5CheckBox;
  newtComponent okButton, cancelButton;
  newtComponent hLine;
  char *newNisDomain, *newNisServer;
  int rc;


  /* create the main form and window */
  mainForm = newtForm(NULL, NULL, 0);
  newtCenteredWindow(60, 16, i18n("Authentication Configuration"));

  /*
   * NIS stuff.
  */
  nisServerLabel = newtLabel(10, 4, i18n("NIS Server:"));
  serverRadios[0] = newtRadiobutton(15, 5, i18n("Request via broadcast"), 
				    (*enableNisServer == ' ' || *enableNis == ' ' ? 1 : 0), NULL);
  serverRadios[1] = newtRadiobutton(15, 6, i18n("Specified:"), 
				    (*enableNisServer == ' ' || *enableNis == ' ' ? 0 : 1), serverRadios[0]);
  
  nisServerEntry = newtEntry(30, 6, "", 25, &newNisServer,
			     NEWT_FLAG_SCROLL);
  nisCheckBox = newtCheckbox(5, 1, i18n("Enable NIS"), 0, 0, enableNis);
  nisLabel = newtLabel(10, 3, i18n("NIS Domain:"));
  nisEntry = newtEntry(30, 3, "", 20, &newNisDomain, 
		       NEWT_FLAG_SCROLL);

  /* if NIS is already enabled, show that. */
  if (strcmp(*nisDomain,"")) {
    newtCheckboxSetValue(nisCheckBox, '*');
    newtEntrySet(nisEntry,*nisDomain, 1);
  }

  /* likewise for a nisserver. */
  if (strcmp(*nisServer,"") && *enableNis == '*') {
    newtEntrySet(nisServerEntry, *nisServer, 1);
  }

  /* horizontal line */
  hLine = newtLabel(2, 7,
		    "--------------------------------------------------------");

  /* Shadow Stuff */
  shadowCheckBox = newtCheckbox(5, 8, i18n("Enable Shadow Passwords"),
				0, 0, enableShadow);
  MD5CheckBox = newtCheckbox(10, 10, i18n("Use MD5 Hashes"),
			     0, 0, useMD5);

  okButton = newtButton(18, 12, i18n("  OK  "));
  cancelButton = newtButton(31, 12, useBack ? i18n(" Back ") : i18n("Cancel"));
  
  /* add the components to the form */
  newtFormAddComponents(mainForm, 
			nisCheckBox, nisLabel, nisEntry,
			nisServerLabel, serverRadios[0], serverRadios[1],
			nisServerEntry,
			hLine,
			shadowCheckBox, MD5CheckBox,
			okButton, cancelButton,
			NULL);

  if (newtRunForm(mainForm) == cancelButton)
    return 1;
  else {
    /* process form values */
    if (newtRadioGetCurrent(serverRadios[0]) == serverRadios[0])
      *enableNisServer = ' ';
    else
      *enableNisServer = '*';

    *nisDomain = newNisDomain;
    *nisServer = newNisServer;
    return 0;
  }
}

/*
 * this function will rewrite /etc/sysconfig/network to have the new
 * value for NISDOMAIN.  If enableNis == ' ', removes this field.
 */
int rewriteNetworkConfigFile(char enableNis, char *nisDomain)
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

    /* look for the line we want */
    if (!strncmp("NISDOMAIN=", s, 10)) {
      /*
       * OK, now instead of this line we want to write the new line,
       * if enableNis is '*'. 
       */
      if (enableNis == '*') {
	fprintf(f1,"NISDOMAIN=%s\n",nisDomain);
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
  if (!found && enableNis == '*')
    fprintf(f1, "NISDOMAIN=%s\n",nisDomain);

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
 * this function will rewrite /etc/sysconfig/yp.conf to have the new
 * value for ypserver.  If enableNisServer == ' ', removes this field.
 */
int rewriteYPConfigFile(char enableNisServer, char *nisServer)
{
  FILE *f, *f1;
  char *s, *s2;
  char buf[250];
  int line = 0;
  int found = 0;

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
      fprintf(f1, s2);
      continue;
    }

    /* next, skip any lines that are comments */
    if (*s == '#') {
      fprintf(f1, s2);
      continue;
    }

    /* look for the line we want */
    if (!strncmp("ypserver ", s, 9)) {
      /*
       * OK, now instead of this line we want to write the new line,
       * if enableNisServer is '*'. 
       */
      if (enableNisServer == '*') {
	fprintf(f1,"ypserver %s\n",nisServer);
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
  if (!found && enableNisServer == '*')
    fprintf(f1, "ypserver %s\n",nisServer);

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

int toggleNisService(char enableNis, int nostart)
{
  if (enableNis == '*') {
    if (!nostart) 
      system("/etc/rc.d/init.d/ypbind start");
    system("/sbin/chkconfig --add ypbind");
  }  else {
    if (!nostart)
      system("/etc/rc.d/init.d/ypbind stop");
    system("/sbin/chkconfig --del ypbind");
  }

  return 0;
}

int doShadowStuff(char enableShadow, char useMD5)
{
  if (enableShadow == '*') {
    system("/usr/sbin/pwconv");
    /* rename the files here, and mess with pam. */
  } else {
    system("/usr/sbin/pwunconv");
    /* etc. etc. */
  }
  return 0;
}

int main(int argc, char **argv) {
  char buf[1024];
  int i, rc;
  FILE *f;
  newtComponent form;
  int back = 0; 
  int test = 0;
  int nostart = 0;
  poptContext optCon;
  struct poptOption options[] = {
    { "back", '\0', 0, &back, 0},
    { "test", '\0', 0, &test, 0},
    { "nostart", '\0', 0, &nostart, 0},
    { 0, 0, 0, 0 }
  };
  char *nisDomain = NULL, *nisServer = NULL;
  char enableNis = ' ', enableNisServer = ' ';
  char enableShadow = ' ', useMD5 = ' ';


  progName = basename(argv[0]);

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

  /* if the test parameter wasn't passed, give an error if not root */
  if (!test && getuid()) {
    fprintf(stderr, i18n("%s: can only be run as root\n"),
	    progName);
    return 2;
  }
  
  /* read the values from the config file */
  if (readNetworkConfigFile(&nisDomain)) {
    fprintf(stderr, i18n("%s: critical error reading /etc/sysconfig/network"),
	    progName);
    return 2;
  }

  if (!nisDomain)
    nisDomain = "";
  else
    enableNis = '*';

  /* read the values from yp.conf */
  if (readYPConfigFile(&nisServer)) {
    fprintf(stderr, i18n("%s: critical error reading /etc/yp.conf"),
	    progName);
    return 2;
  }

  if (!nisServer)
    nisServer = "";
  else
    enableNisServer = '*';

  newtInit();
  newtCls();

  newtPushHelpLine(i18n(" <Tab>/<Alt-Tab> between elements   |   <Space> selects   |  <F12> next screen"));
  newtDrawRootText(0, 0, "authconfig " VERSION " - (c) 1999 Red Hat Software");

  if (getChoices(back, &enableNis, &nisDomain, 
		 &enableNisServer, &nisServer, 
		 &enableShadow, &useMD5)) {
    /* cancelled */
    newtFinished();

    if (nisDomain && test) {
      fprintf(stderr, 
	      i18n("%s: nis domain was set to %s, but dialog was cancelled\n"),
	      progName, nisDomain);
      return 2;
    }

    return 1;
  }

  newtFinished();
  
  if (test) {
    fprintf(stderr, 
	    i18n("return values: nis: %c, nisdomain: %s, "
		 "shadow: %c, md5: %c\n"),
	    enableNis, nisDomain, enableShadow, useMD5);
    return 0;
  }

  /* here, we write the config files / activate changes. */
  if (rewriteNetworkConfigFile(enableNis, nisDomain)) {
    fprintf(stderr, i18n("%s: critical error writing /etc/sysconfig/network\n"),
	    progName);
    return 2;
  }

  if (rewriteYPConfigFile(enableNisServer, nisServer)) {
    fprintf(stderr, i18n("%s: critical error writing /etc/yp.conf\n"),
	    progName);
    return 2;
  }

  if (toggleNisService(enableNis, nostart)) {
    fprintf(stderr, i18n("%s: critical error turning on NIS service\n"),
	    progName);
    return 2;
  }
      
  if (doShadowStuff(enableShadow, useMD5)) {
    fprintf(stderr, i18n("%s: critical error with shadow password manipulation\n"),
	    progName);
    return 2;
  }

  return 0;
}
