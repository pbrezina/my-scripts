 /*
  * Authconfig - client authentication configuration program
  * Copyright (c) 2001 Red Hat, Inc.
  *
  * Authors: Nalin Dahyabhai <nalin@redhat.com>
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

#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <glade/glade-xml.h>
#include "authinfo.h"
#ifdef LOCAL_POLICIES
#include "localpol.h"
#endif

#define XMLNAME "XML"
#define AUTHINFONAME "AUTHINFO"
#define GLADEFILE (DATADIR "/" PACKAGE "/" PACKAGE ".glade")

/* A structure which maps checkbox names (as defined in the GLADE file) to
 * paths of binaries, the name of what they enable, and the name of the package
 * which contains the binary.  We use this to warn the user if something she
 * enabled isn't installed. */
struct package_needed_warning {
	const char *name, *path, *service, *package;
};

static struct package_needed_warning package_needed_warnings[] = {
	{"enablecache", PATH_NSCD, "caching", "nscd"},
	{"enablenis", PATH_YPBIND, "NIS", "ypbind"},
	{"enableldap", PATH_LIBNSS_LDAP, "LDAP", "nss_ldap"},
	{"enableldapauth", PATH_PAM_LDAP, "LDAP", "nss_ldap"},
	{"enablekerberos", PATH_PAM_KRB5, "Kerberos", "pam_krb5"},
	{"enablesmb", PATH_PAM_SMB, "SMB", "pam_smb"},
};

/* A structure mapping widget names (as defined in the GLADE file) to GType
 * values (WARNING: only G_TYPE_BOOLEAN and G_TYPE_STRING are used, so don't
 * go crazy if you modify this) and offsets in the authInfo structure. */
struct config_map {
	const char *name;
	GType type;
	size_t offset;
};

/* Config map for the main dialog. */
static struct config_map mainsettings[] = {
	{"enablecache", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableCache)},
	{"enablehesiod", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableHesiod)},
	{"enablenis", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableNIS)},
	{"enableldap", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableLDAP)},
	{"enableshadow", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableShadow)},
	{"enablemd5", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableMD5)},
	{"enablekerberos", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableKerberos)},
	{"enableldapauth", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableLDAPAuth)},
	{"enablesmb", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableSMB)},
	{NULL, 0, 0},
};

/* Config map for the hesiod settings dialog. */
static struct config_map hesiodsettings[] = {
	{"lhs", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, hesiodLHS)},
	{"rhs", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, hesiodRHS)},
	{NULL, 0, 0},
};

/* Config map for the kerberos settings dialog. */
static struct config_map kerberossettings[] = {
	{"realm", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, kerberosRealm)},
	{"kdc", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, kerberosKDC)},
	{"adminserver", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, kerberosAdminServer)},
	{NULL, 0, 0},
};

/* Config map for the LDAP settings dialog. */
static struct config_map ldapsettings[] = {
	{"tls", G_TYPE_BOOLEAN,
	 G_STRUCT_OFFSET(struct authInfoType, enableLDAPS)},
	{"basedn", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, ldapBaseDN)},
	{"server", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, ldapServer)},
	{NULL, 0, 0},
};

/* Config map for the NIS settings dialog. */
static struct config_map nissettings[] = {
	{"domain", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, nisDomain)},
	{"server", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, nisServer)},
	{NULL, 0, 0},
};

/* Config map for the SMB settings dialog. */
static struct config_map smbsettings[] = {
	{"workgroup", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, smbWorkgroup)},
	{"domaincontrollers", G_TYPE_STRING,
	 G_STRUCT_OFFSET(struct authInfoType, smbServers)},
	{NULL, 0, 0},
};

/* A structure button names (as defined in the GLADE file) to the names
 * (again, as defined in the GLADE file) of dialog boxes to pop up if the
 * user clicks on the button. */
struct config_dialog {
	const char *name, *dialog;
	struct config_map *map;
};
static struct config_dialog config_dialogs[] = {
	{"confignis", "nissettings", nissettings},
	{"confighesiod", "hesiodsettings", hesiodsettings},
	{"configldap", "ldapsettings", ldapsettings},
	{"configldapauth", "ldapsettings", ldapsettings},
	{"configkerberos", "kerberossettings", kerberossettings},
	{"configsmb", "smbsettings", smbsettings},
};

/* Pop up a warning box warning the user that the package needed to use the
 * facility she's just enabled isn't installed. */
static void
check_warn(GtkWidget *widget, struct package_needed_warning *warning)
{
	GtkWidget *dialog;

	if (access(warning->path, R_OK) == 0) {
		return;
	}
	if (GTK_IS_CHECK_BUTTON(widget)) {
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) {
			dialog = gtk_message_dialog_new(NULL,
							0,
							GTK_MESSAGE_WARNING,
							GTK_BUTTONS_CLOSE,
							AUTHCONFIG_PACKAGE_WARNING,
							warning->path,
							warning->service,
							warning->package);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
		}
	}
}

/* Set the contents of a widget using a field from the structure. */
static void
set_config(GladeXML *xml, struct authInfoType *authInfo, struct config_map *map)
{
	int i;
	gboolean bval;
	char *sval;
	GtkWidget *widget;
	for(i = 0; map[i].name != NULL; i++) {
		/* Get the widget. */
		widget = glade_xml_get_widget(xml, map[i].name);
		switch(map[i].type) {
			/* It's a boolean variable?  Set the checkbox. */
			case G_TYPE_BOOLEAN:
				g_assert(GTK_IS_CHECK_BUTTON(widget));
				bval = G_STRUCT_MEMBER(gboolean,
						       authInfo,
						       map[i].offset);
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget),
							     bval);
							     
				break;
			/* It's a string?  Set the entry field. */
			case G_TYPE_STRING:
				g_assert(GTK_IS_ENTRY(widget));
				sval = G_STRUCT_MEMBER(char *,
						       authInfo,
						       map[i].offset);
				gtk_entry_set_text(GTK_ENTRY(widget), sval ?: "");
				break;
		}
	}
}

/* Set the state/content of a field of the authInfo structure using a widget. */
static void
get_config(GtkWidget *widget, struct config_map *map)
{
	int i;
	gboolean bval;
	char *sval;
	const char *text;
	struct authInfoType *authInfo;
	GladeXML *xml;

	authInfo = g_object_get_data(G_OBJECT(widget), AUTHINFONAME);
	xml = g_object_get_data(G_OBJECT(widget), XMLNAME);

	for(i = 0; map[i].name != NULL; i++) {
		/* Get the address of the widget. */
		widget = glade_xml_get_widget(xml, map[i].name);
		switch(map[i].type) {
			case G_TYPE_BOOLEAN:
				/* Set the boolean using a checkbox. */
				g_assert(GTK_IS_CHECK_BUTTON(widget));
				bval = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
				G_STRUCT_MEMBER(gboolean,
						authInfo,
						map[i].offset) = bval;
				break;
			case G_TYPE_STRING:
				/* Set the text using an entry field. */
				g_assert(GTK_IS_ENTRY(widget));
				text = gtk_entry_get_text(GTK_ENTRY(widget));
				sval = text ? g_strdup(text) : NULL;
				g_free(G_STRUCT_MEMBER(char *,
						       authInfo,
						       map[i].offset));
				G_STRUCT_MEMBER(char *,
						authInfo,
						map[i].offset) = sval;
				break;
		}
	}
}

/* Construct and show a dialog given its name, using the passed-in widget
 * to carry the address of the GladeXML object and the authInfo structure. */
static void
show_dialog(GtkWidget *widget, struct config_dialog *dialog)
{
	GladeXML *xml;
	GtkWidget *window;
	struct authInfoType *authInfo;

	/* Construct a new widget tree using the GLADE file and	make
	 * the window modal. */
	xml = glade_xml_new(GLADEFILE, dialog->dialog, PACKAGE);
	g_assert(xml != NULL);
	window = glade_xml_get_widget(xml, dialog->dialog);
	g_assert(GTK_IS_WINDOW(window));
	gtk_window_set_modal(GTK_WINDOW(window), TRUE);

	/* Get the address of the authinfo structure. */
	authInfo = g_object_get_data(G_OBJECT(widget), AUTHINFONAME);
	g_assert(authInfo != NULL);

	/* Read the structure, and initialize the dialog using data in it. */
	set_config(xml, authInfo, dialog->map);

	/* If the user hits the cancel button, delete the dialog. */
	widget = glade_xml_get_widget(xml, "cancel");
	g_signal_connect_swapped(G_OBJECT(widget), "clicked",
				 GTK_SIGNAL_FUNC(gtk_widget_destroy), window);

	/* If the user hits the okay button, we want to save the settings to
	 * the structure, and then delete the dialog. */
	widget = glade_xml_get_widget(xml, "ok");
	g_object_set_data(G_OBJECT(widget), AUTHINFONAME, authInfo);
	g_object_set_data(G_OBJECT(widget), XMLNAME, xml);

	g_signal_connect(G_OBJECT(widget), "clicked",
			 GTK_SIGNAL_FUNC(get_config), dialog->map);
	g_signal_connect_swapped(G_OBJECT(widget), "clicked",
				 GTK_SIGNAL_FUNC(gtk_widget_destroy),
				 window);

	/* All done here. */
	gtk_widget_show_all(window);
}

/* Callback to save the information and do the post-save stuff. */
static void
save_info(GtkWidget *ignored, struct authInfoType *authInfo)
{
	if(authInfoWrite(authInfo) == FALSE) {
		g_warning(i18n("%s: critical error writing configuration"),
			  PACKAGE);
	} else {
		authInfoPost(authInfo, FALSE);
	}
}

/* Create the main dialog for the application. */
static void
create_main_window(struct authInfoType *authInfo)
{
	GladeXML *xml;
	GtkWidget *window, *widget;
	int i;

	/* Tell libglade to construct the main dialog. */
	xml = glade_xml_new(GLADEFILE, "authconfig", PACKAGE);
	g_assert(xml != NULL);
	glade_xml_signal_autoconnect(xml);

	/* Attach warnings to each of the toggle buttons in the main dialogs. */
	for(i = 0; i < G_N_ELEMENTS(package_needed_warnings); i++) {
		widget = glade_xml_get_widget(xml,
					      package_needed_warnings[i].name);
		g_assert(GTK_IS_CHECK_BUTTON(widget));
		g_signal_connect(G_OBJECT(widget), "toggled",
				 GTK_SIGNAL_FUNC(check_warn),
				 &package_needed_warnings[i]);
	}

	/* Attach the XML object and authInfo structure to each of the buttons
	 * which launch dialogs. */
	for(i = 0; i < G_N_ELEMENTS(config_dialogs); i++) {
		widget = glade_xml_get_widget(xml,
					      config_dialogs[i].name);
		g_assert(GTK_IS_BUTTON(widget));
		g_object_set_data(G_OBJECT(widget), XMLNAME, xml);
		g_object_set_data(G_OBJECT(widget), AUTHINFONAME, authInfo);
		g_signal_connect(G_OBJECT(widget), "clicked",
				 GTK_SIGNAL_FUNC(show_dialog),
				 &config_dialogs[i]);
	}

	/* Initialize the widgets using the authInfo structure. */
	set_config(xml, authInfo, mainsettings);

	/* When the user hits "ok", we need to read the settings from the
	 * dialog, save her settings to disk, and quit. */
	widget = glade_xml_get_widget(xml, "ok");
	g_assert(GTK_IS_BUTTON(widget));
	g_object_set_data(G_OBJECT(widget), AUTHINFONAME, authInfo);
	g_object_set_data(G_OBJECT(widget), XMLNAME, xml);
	g_signal_connect(G_OBJECT(widget), "clicked",
			 GTK_SIGNAL_FUNC(get_config), mainsettings);
	g_signal_connect_after(G_OBJECT(widget), "clicked",
			       GTK_SIGNAL_FUNC(save_info), authInfo);
	g_signal_connect_swapped(G_OBJECT(widget), "clicked",
				 GTK_SIGNAL_FUNC(gtk_main_quit), NULL);

	/* When the user hits "cancel", we just need to quit. */
	widget = glade_xml_get_widget(xml, "cancel");
	window = glade_xml_get_widget(xml, "authconfig");
	g_signal_connect_swapped(G_OBJECT(widget), "clicked",
				 GTK_SIGNAL_FUNC(gtk_main_quit), window);

	/* All done here. */
	gtk_widget_show(window);
}

int
main(int argc, char **argv)
{
	struct authInfoType *authInfo = NULL;

	/* Tell gettext where the messages for this package, then make this
	 * package the default domain for messages. */
	bindtextdomain(PACKAGE, DATADIR "/locale");
	textdomain(PACKAGE);

	/* We can't really do anything unless we're root, so bail if we're
	 * not the superuser. */
	if(getuid() != 0) {
		fprintf(stderr, i18n("%s: can only be run as root\n"),
			PACKAGE);
		return 2;
	}

	/* Read the current configuration. */
	authInfo = authInfoRead();
	if (authInfo == NULL) {
		g_error(i18n("%s: critical error reading system configuration"),
			PACKAGE);
	}

	/* Initialize GTK, create the main dialog, and run with it. */
	gtk_init(&argc, &argv);
	gtk_set_locale();
	create_main_window(authInfo);
	gtk_main();

	return 0;
}
