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
  char newEnableShadow, newUseMD5;

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
				0, 0, &newEnableShadow);
  MD5CheckBox = newtCheckbox(10, 10, i18n("Use MD5 Hashes"),
			     0, 0, &newUseMD5);

  if (*enableShadow == '*')
    newtCheckboxSetValue(shadowCheckBox, '*');

  if (*useMD5 == '*')
    newtCheckboxSetValue(MD5CheckBox, '*');

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

    *enableShadow = newEnableShadow;
    *useMD5 = newUseMD5;
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
int rewriteYPConfigFile(char enableNisServer, char *nisServer, char *nisDomain)
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
    } else if (!strncmp("server ", s, 7)) {
      if (enableNisServer == '*') {
	fprintf(f1, "server %s\n",nisServer);
	found = 1;
      }
    } else if (!strncmp("domain ", s, 7)) {
      if (enableNisServer == '*') {
	fprintf(f1, "domain %s\n",nisDomain);
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
  if (!found && enableNisServer == '*') {
    fprintf(f1, "domain %s\n",nisDomain);
    fprintf(f1, "server %s\n",nisServer);
    fprintf(f1,"# the following line is for backwards compatibility with libc5-based programs\n");
    fprintf(f1, "ypserver %s\n",nisServer);
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

	if (enable) {
	  if (md5) {
	    s = realloc(s, sizeof(char *) * (strlen(s) + 5));
	    strcat(s, " md5");
	  }
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

int checkUseMD5(char *useMD5)
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
	*useMD5 = '*';
    }
  }
  
  fclose(f);
  return 0;
}

int doShadowStuff(char enableShadow, char useMD5)
{
  /* first, toggle the shadow service for all required pam modules. */
  if (toggleShadowPam((enableShadow == '*' ? 1 : 0),
		      (useMD5 == '*' ? 1 : 0)))
    return 1;
  
  /* now, do file manipulation on the password files themselves. */
  if (enableShadow == '*') {
    system("/usr/sbin/pwconv");
  } else {
    system("/usr/sbin/pwunconv");
  }
  return 0;
}

int main(int argc, char **argv) {
  int rc;
  struct stat sb;

  char *nisDomain = NULL, *nisServer = NULL;
  char enableNis = ' ', enableNisServer = ' ';
  char enableShadow = ' ', useMD5 = ' ';

  int back = 0, test = 0, nostart = 0;
  int kickstart = 0;
  int enablenis = 0, enableshadow = 0, usemd5 = 0;
  poptContext optCon;
  struct poptOption options[] = {
    { "back", '\0', 0, &back, 0},
    { "test", '\0', 0, &test, 0},
    { "nostart", '\0', 0, &nostart, 0},
    { "ks", '\0', 0, &kickstart, 0},
    { "enablenis", '\0', 0, &enablenis, 0},
    { "nisdomain", '\0', POPT_ARG_STRING, nisDomain, 0},
    { "nisserver", '\0', POPT_ARG_STRING, nisServer, 0},
    { "enableshadow", '\0', 0, &enableshadow, 0},
    { "usemd5", '\0', 0, &usemd5, 0},
    { 0, 0, 0, 0 }
  };

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

  /* process other arguments */
  if (enablenis)
    enableNis = '*';
  if (enableshadow)
    enableShadow = '*';
  if (usemd5)
    useMD5 = '*';

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

  if (!stat("/etc/shadow", &sb))
    enableShadow = '*';

  if (checkUseMD5(&useMD5)) {
    fprintf(stderr, i18n("%s: critical error reading /etc/pam.d/passwd\n"),
	    progName);
    return 2;
  }

  if (!kickstart) {
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
  } /* kickstart */
  
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

  if (rewriteYPConfigFile(enableNisServer, nisServer, nisDomain)) {
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
