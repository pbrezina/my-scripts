#!/usr/bin/python2.2
import gettext, gtk, gtk.glade, authconfig
import signal
import sys
from rhpl.translate import _, textdomain

class childWindow:
	def __init__(self):
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
			"enableshadow" :
			("enableShadow", "", "", ""),
			"enablemd5" :
			("enableMD5", "", "", ""),
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

	def destroy_widget(self, button, widget):
		widget.destroy()

	# Toggle a boolean.
	def toggleboolean(self, button, name):
		setattr(self.info, name, button.get_active())
		return

	# Create a vbox or dialog using the file, and return it. */
	def run_on_button(self, button, top, mapname, parent=None):
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    top, "authconfig")
		map = getattr(self, mapname)
		assert (map)
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if hasattr(widget, "get_text"):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))

			elif hasattr(widget, "get_active"):
				widget.set_active(getattr(self.info,
							  map[entry][0]))
		dialog = xml.get_widget(top)
		if parent:
			dialog.set_transient_for (parent)
		dialog.set_resizable (gtk.FALSE)
		if dialog.run () == gtk.RESPONSE_OK:
			for entry in map.keys():
				widget = xml.get_widget(entry)
				if hasattr(widget, "get_text"):
					setattr(self.info, map[entry][0], widget.get_text())

				elif hasattr(widget, "get_active"):
					setattr(self.info, map[entry][0], widget.get_active())
		dialog.destroy()
		return

	# Create a vbox with the right controls and return the vbox. */
	def get_main_widget(self):
		dialog = gtk.Dialog (_("Authentication Configuration"),
				     None,
				     gtk.DIALOG_NO_SEPARATOR,
				     (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
				      gtk.STOCK_OK, gtk.RESPONSE_OK))
		dialog.set_resizable (gtk.FALSE)
		# Construct the XML object.
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    'vbox', "authconfig")
		box = xml.get_widget('vbox')
		box.show_all
		dialog.vbox.pack_start (box)

		# Set up the pushbuttons to launch new dialogs.
		for entry in self.launch_map.keys():
			button = xml.get_widget(entry)
			button.connect("clicked", self.run_on_button,
				       self.launch_map[entry][0],
				       self.launch_map[entry][1],
				       dialog)

		# Hook up checkboxes and entry fields.
		for entry in self.main_map.keys():
			widget = xml.get_widget(entry)
			if hasattr(widget, "get_active"):
				widget.set_active(getattr(self.info,
							  self.main_map[entry][0]))
				widget.connect("toggled", self.toggleboolean,
					       self.main_map[entry][0])

		return dialog

	# Save changes.
	def apply(self, button = None):
		self.info.write()
		self.info.post(1)
		return

# Fake the firstboot setup.
if __name__ == '__main__':
	signal.signal (signal.SIGINT, signal.SIG_DFL)
	textdomain("authconfig")
	gtk.glade.bindtextdomain("authconfig", "/usr/share/locale")
	module = childWindow()
	dialog = module.get_main_widget()
	if dialog.run () == gtk.RESPONSE_OK:
		module.apply ()
	sys.exit (0)

