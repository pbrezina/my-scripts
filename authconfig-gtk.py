#!/usr/bin/python2.2
import gettext, gtk, gtk.glade, authconfig;

class childWindow:
	def __init__(self):
		gettext.bindtextdomain("authconfig", "/usr/share/locale")
		self.runPriority = 45
		self.moduleName = "Authentication"
		self.moduleClass = "reconfig"
		self.main_map = {
			"enablecache" :
			("enableCache", "/usr/sbin/nscd",
			 "caching", "nscd"),
			"enablenis" :
			("enableNIS", "/usr/sbin/ypbind",
			 "NIS", "ypbind"),
			"enablehesiod" :
			("enableHesiod", "/lib/libnss_hesiod.so.2",
			 "Hesiod", "glibc"),
			"enableldap" :
			("enableLDAP", "/lib/libnss_ldap.so.2",
			 "LDAP", "nss_ldap"),
			"enableldapauth" :
			("enableLDAPAuth", "/lib/security/pam_ldap.so",
			 "LDAP", "nss_ldap"),
			"enablekerberos" :
			("enableKerberos", "/lib/security/pam_krb5.so",
			 "Kerberos", "pam_krb5"),
			"enablesmb" :
			("enableSMB", "/lib/security/pam_smb_auth.so",
			 "SMB", "pam_smb"),
		}
		self.nis_map = {
			"domain" : ("nisDomain", ""),
			"server" : ("nisServer", ""),
		}
		self.kerberos_map = {
			"realm" : ("kerberosRealm", ""),
			"kdc" : ("kerberosKDC", ""),
			"adminserver" : ("kerberosAdminServer", ""),
		}
		self.ldap_map = {
			"tls" : ("enableLDAPS", ""),
			"basedn" : ("ldapBaseDN", ""),
			"server" : ("ldapServer", ""),
		}
		self.hesiod_map = {
			"lhs" : ("hesiodLHS", ""),
			"rhs" : ("hesiodRHS", ""),
		}
		self.smb_map = {
			"workgroup" : ("smbWorkgroup", ""),
			"domaincontrollers" : ("smbServers", ""),
		}
		self.launch_map = {
			"confignis": ("nissettings", "nis_map"),
			"configldap": ("ldapsettings", "ldap_map"),
			"configldapauth": ("ldapsettings", "ldap_map"),
			"confighesiod": ("hesiodsettings", "hesiod_map"),
			"configsmb": ("smbsettings", "smb_map"),
			"configkerberos": ("kerberossettings", "kerberos_map"),
		}
		self.info = authconfig.read()

	def gettext(self, String):
		return gettext.dgettext("authconfig", String)

	# Toggle a boolean.
	def toggleboolean(self, button, name):
		setattr(self.info, name, button.get_active())
		return

	# Toggle a string.
	def togglestring(self, entry, name):
		setattr(self.info, name, entry.get_text())
		return

	# Destroy a widget.
	def destroy_widget(self, button, widget):
		widget.destroy()

	# Create a vbox or dialog using the file, and return it. */
	def run_on_button(self, button, top = "vbox", mapname = "main_map"):
		box, header = self.launch(top, mapname)
		box.show()
		return

	# Create a vbox with the right controls and return the vbox. */
	def launch(self, top = "vbox", mapname = "main_map"):
		# Construct the XML object.
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    top, "authconfig")
		box = xml.get_widget(top)
		header = None

		# Do setup that's specific to the toplevel.
		if ((top == "vbox") and (mapname == "main_map")):

			# Set up the pushbuttons to launch new dialogs.
			for entry in self.launch_map.keys():
				button = xml.get_widget(entry)
				button.connect("clicked", self.run_on_button,
					       self.launch_map[entry][0],
					       self.launch_map[entry][1])

			# Create a header.
			header = gtk.HBox()
			header.set_border_width(0)
			image = gtk.Image()
			image.modify_bg(gtk.STATE_NORMAL, gtk.gdk.color_parse ("#cc0000"))
			try:
				image.set_from_file("/usr/share/firstboot/pixmaps/authconfig.png")
				header.pack_start(image, gtk.FALSE, gtk.TRUE, 5)
			except:
				try:
					image.set_from_file("/usr/share/authconfig/authconfig.png")
					header.pack_start(image, gtk.FALSE, gtk.TRUE, 5)
				except:
					pass
			label = gtk.Label(self.gettext("Authentication Configuration"))
			label.modify_fg(gtk.STATE_NORMAL, gtk.gdk.color_parse ("#ffffff"))
			label.modify_bg(gtk.STATE_NORMAL, gtk.gdk.color_parse ("#cc0000"))
			header.pack_start(label)
			header.show_all()

			box.pack_start(header, gtk.FALSE, gtk.FALSE, 0)
			box.reorder_child(header, 0)

		# Have a "close" button, if we have one, close the window.
		button = xml.get_widget("close")
		if button:
			button.connect("clicked", self.destroy_widget, box)

		# Find the map, which might have been passed in by name.
		map = None
		if getattr(self, mapname):
			map = getattr(self, mapname)

		# Hook up checkboxes and entry fields.
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if hasattr(widget, "get_text"):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))
				widget.connect("changed", self.togglestring,
					       map[entry][0])
			elif hasattr(widget, "get_active"):
				widget.set_active(getattr(self.info,
							  map[entry][0]))
				widget.connect("toggled", self.toggleboolean,
					       map[entry][0])

		box.show()

		return (box, header)

	# Save changes.
	def apply(self, button = None):
		self.info.write()
		self.info.post(1)
		return

# Fake the firstboot setup.
if __name__ == '__main__':
	import gettext
	def _(String):
		return gettext.dgettext("authconfig", String)
	module = childWindow()
	win = gtk.Window()
	win.set_title(_("Authentication Configuration"))
	box = gtk.VBox()

	hbox = gtk.HButtonBox()
	hbox.show()

	vbox, eventbox = module.launch()
	vbox.show()
	eventbox.destroy()

	button = gtk.Button(_("Ok"), gtk.STOCK_OK);
	button.connect("clicked", module.apply)
	button.show()
	hbox.pack_start_defaults(button)

	button = gtk.Button(_("Cancel"), gtk.STOCK_CANCEL);
	button.connect("clicked", gtk.mainquit)
	button.show()
	hbox.set_spacing(30)
	hbox.set_border_width(8)
	hbox.set_layout(gtk.BUTTONBOX_END)
	hbox.pack_start_defaults(button)

	box.pack_start_defaults(vbox)
	box.pack_start_defaults(hbox)
	box.show()

	win.add(box)
	win.connect("delete_event", gtk.mainquit)
	win.show()
	gtk.main()
