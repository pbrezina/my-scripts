#!/usr/bin/python
import authconfig, gettext, os, signal, sys
from rhpl.translate import _, textdomain

firstbootservices = [
	"dovecot",
	"messagebus",
	"postfix",
	"privoxy",
	"radiusd",
	"rstatd",
	"rusersd",
	"rwalld",
	"rwhod",
	"saslauthd",
	"sendmail",
	"smb",
	"squid",
	"sshd",
	"vncserver",
	"vsftpd",
	"winbind"
]

if "--nox" in sys.argv:
	os.execv('/usr/bin/authconfig',('authconfig',))
	sys.exit(1)

try:
	import gtk, gtk.glade
except RuntimeError, e:
	if (os.isatty(sys.stdin.fileno()) and
	    os.isatty(sys.stdout.fileno()) and
	    os.isatty(sys.stderr.fileno())):
		os.execv('/usr/bin/authconfig',('authconfig',))
		sys.exit(1)
	else:
		raise e

class childWindow:
	def __init__(self):
		self.runPriority = 45
		self.moduleName = "Authentication"
		self.moduleClass = "reconfig"
		self.lib = "/lib"
		for item in sys.path:
			for element in item.split("/"):
				if element.startswith("lib"):
					self.lib = "/" + element
		# "checkbox/button name": authInfo field, file, generic name,
		# package, names of widgets to disable if checkbox not active
		self.main_map = {
			"enablecache" :
			("enableCache", "/usr/sbin/nscd",
			 "caching", "nscd", []),
			"enablenis" :
			("enableNIS", "/usr/sbin/ypbind",
			 "NIS", "ypbind", ["confignis"]),
			"enablehesiod" :
			("enableHesiod", self.lib + "/libnss_hesiod.so.2",
			 "Hesiod", "glibc", ["confighesiod"]),
			"enableldap" :
			("enableLDAP", self.lib + "/libnss_ldap.so.2",
			 "LDAP", "nss_ldap", ["configldap"]),
			"enableldapauth" :
			("enableLDAPAuth", self.lib + "/security/pam_ldap.so",
			 "LDAP", "nss_ldap", ["configldapauth"]),
			"enablekerberos" :
			("enableKerberos", self.lib + "/security/pam_krb5.so",
			 "Kerberos", "pam_krb5", ["configkerberos"]),
			"enablesmb" :
			("enableSMB", self.lib + "/security/pam_smb_auth.so",
			 "SMB", "pam_smb", ["configsmb"]),
			"enableshadow" :
			("enableShadow", "", "", "", []),
			"enablemd5" :
			("enableMD5", "", "", "", []),
			"enablewinbind" :
			("enableWinbind", self.lib + "/nss_winbind.so.2",
			 "winbind", "samba-client", ["configwinbind"]),
			"enablewinbindauth" :
			("enableWinbindAuth", self.lib + "/security/pam_winbind.so",
			 "winbind", "samba-client", ["configwinbindauth"]),
		}
		# entry or label / button / checkbox / option menu :
		# entry (or label): authInfo field
		# button: function
		# checkbox: authInfo field
		# option menu: authInfo field, list of choices, list of tuples
		#              of value/sensitive widgets
		self.empty_map = {
		}
		self.nis_map = {
			"domain" : ("nisDomain", ""),
			"server" : ("nisServer", ""),
		}
		self.kerberos_map = {
			"realm" : ("kerberosRealm", ""),
			"kdc" : ("kerberosKDC", ""),
			"adminserver" : ("kerberosAdminServer", ""),
			"dnsrealm" : ("kerberosRealmviaDNS", ""),
			"dnskdc" : ("kerberosKDCviaDNS", ""),
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
		self.winbindjoin_map = {
			"domain" : ("smbWorkgroup", ""),
			"joinuser" : ("joinUser", ""),
			"joinpassword" : ("joinPassword", ""),
		}
		self.winbind_map = {
			"domain" : ("smbWorkgroup", ""),
			"security" : ("smbSecurity", ("ads", "domain", "server", "user"), (("realm", ("ads",)), ("shell", ("domain", "ads")), ("join", ("domain", "ads")))),
			"realm" : ("smbRealm", ""),
			"servers" : ("smbServers", ""),
			"shell" : ("winbindTemplateShell", ["/bin/false"] + authconfig.getusershells(), ()),
			"join" : ("winbindjoin_maybe_launch", "")
		}
		self.launch_map = {
			"confignis": ("nissettings", "nis_map"),
			"configldap": ("ldapsettings", "ldap_map"),
			"configldapauth": ("ldapsettings", "ldap_map"),
			"confighesiod": ("hesiodsettings", "hesiod_map"),
			"configsmb": ("smbsettings", "smb_map"),
			"configkerberos": ("kerberossettings", "kerberos_map"),
			"configwinbind": ("winbindsettings", "winbind_map"),
			"configwinbindauth": ("winbindsettings", "winbind_map"),
		}
		self.info = authconfig.read()
		return

	def destroy_widget(self, button, widget):
		widget.destroy()
		return

	def winbindjoin_maybe_launch(self, button, map, xml, parent):
		backup = self.info.copy()
		pristine = authconfig.read()
		self.info_apply(map, xml)
		if self.info.differs(pristine):
			response = self.run_on_button(self, "joinsave",
						      "empty_map", parent,
						      (0, 1))
			if (response == gtk.RESPONSE_CANCEL):
				return
			# Don't save.
			if (response == 0):
				self.info = backup
			# Save.
			if (response == 1):
				self.apply()
				backup = self.info
		self.winbindjoin_launch(button, map, xml, parent)
		self.info = backup

	def winbindjoin_launch(self, button, map, xml, parent):
		if not self.info.joinUser:
			self.info.joinUser = "Administrator"
		response = self.run_on_button(self, "winbindjoin",
					      "winbindjoin_map", parent)
		if (response == gtk.RESPONSE_OK):
			self.info.join()
		self.info.joinUser = None
		self.info.joinPassword = None

	def info_apply(self, map, xml):
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.OptionMenu()):
				history = widget.get_history()
				setattr(self.info, map[entry][0],
					widget.get_data('option_list')[history])
			if type(widget) == type(gtk.Entry()):
				setattr(self.info, map[entry][0],
					widget.get_text())
			if type(widget) == type(gtk.CheckButton()):
				setattr(self.info, map[entry][0],
					widget.get_active())
		self.info.update()

	# Toggle a boolean.
	def toggleboolean(self, checkbox, name, aliases, dependents):
		setattr(self.info, name, checkbox.get_active())
		for widget in aliases:
			widget.set_active(checkbox.get_active())
		for widget in dependents:
			widget.set_sensitive(checkbox.get_active())
		return

	def changeoption(self, optionmenu, entry, xml):
		history = optionmenu.get_history()
		options = optionmenu.get_data("option_list")
		for candidate in entry[2]:
			dependent = xml.get_widget(candidate[0])
			if options[history] in candidate[1]:
				dependent.set_sensitive(gtk.TRUE)
			else:
				dependent.set_sensitive(gtk.FALSE)

	# Create a vbox or dialog using the file, and return it. */
	def run_on_button(self, button, top, mapname, parent=None, responses=()):
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    top, "authconfig")
		map = getattr(self, mapname)
		dialog = xml.get_widget(top)
		self.info.update()
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.OptionMenu()):
				widget = xml.get_widget(entry)
				menu = gtk.Menu()
				options = []
				history = 0
				offset = 0
				for option in tuple(map[entry][1]):
					if option == '':
						continue
					item = gtk.MenuItem(option)
					item.show()
					menu.append(item)
					options.append(option)
					if option == getattr(self.info, map[entry][0]):
						history = offset
					offset = offset + 1
				widget.set_menu(menu)
				option = getattr(self.info, map[entry][0])
				if option not in options:
					if option != '':
						item = gtk.MenuItem(option)
						item.show()
						menu.prepend(item)
						options.insert(0, option)
						history = 0
				widget.set_history(history)
				widget.set_data('option_list', options)
				widget.connect("changed", self.changeoption,
					       map[entry], xml)
				self.changeoption(widget, map[entry], xml)
			if type(widget) == type(gtk.Button()):
				widget.connect("clicked",
					       getattr(self, map[entry][0]),
					       map,
					       xml,
					       dialog)
			if type(widget) == type(gtk.Entry()):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))

			if type(widget) == type(gtk.CheckButton()):
				widget.set_active(getattr(self.info,
							  map[entry][0]))
				if len(map[entry]) > 4:
					button = xml.get_widget(map[entry][4])
					button.set_sensitive(getattr(self.info,
								     map[entry][0]))
			if type(widget) == type(gtk.Label()):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))
		if parent:
			dialog.set_transient_for(parent)
			parent.set_sensitive(gtk.FALSE)
		dialog.set_resizable(gtk.FALSE)
		response = None
		while ((response != gtk.RESPONSE_OK) and
		       (response != gtk.RESPONSE_CANCEL) and
		       (response not in responses)):
			response = dialog.run()
		if (response == gtk.RESPONSE_OK):
			self.info_apply(map, xml)
		dialog.destroy()
		if parent:
			parent.set_sensitive(gtk.TRUE)
		return response

	# Create a vbox with the right controls and return the vbox. */
	def get_main_widget(self):
		dialog = gtk.Dialog(_("Authentication Configuration"),
				    None,
				    gtk.DIALOG_NO_SEPARATOR,
				    (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
				     gtk.STOCK_OK, gtk.RESPONSE_OK))
		dialog.set_resizable(gtk.FALSE)
		# Construct the XML object.
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    'vbox', "authconfig")
		box = xml.get_widget('vbox')
		box.show_all
		dialog.vbox.pack_start(box)

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
			widget.set_active(getattr(self.info,
						  self.main_map[entry][0]))
			if hasattr(widget, "get_active"):
				aliases = []
				dependents = []
				for candidate in self.main_map.keys():
					if entry != candidate:
						if self.main_map[entry][0] == self.main_map[candidate][0]:
							aliases = aliases + [xml.get_widget(candidate)]
				for candidate in self.main_map[entry][4]:
					dependents = dependents + [xml.get_widget(candidate)]
				widget.connect("toggled", self.toggleboolean,
					       self.main_map[entry][0], aliases,
					       dependents)
				self.toggleboolean(widget,
						   self.main_map[entry][0],
						   aliases,
						   dependents)
		return dialog

	# Save changes.
	def apply(self, button = None):
		self.info.write()
		self.info.post(1)
		if "--firstboot" in sys.argv:
			for service in firstbootservices:
				if os.access("/etc/init.d/" + service, os.X_OK):
					os.system("/etc/init.d/" + service + " condrestart")
			if os.access("/etc/init.d/autofs", os.X_OK):
    				if self.info.enableNIS:
					cond = ""
				else:
    					cond = "cond"
				os.system("/etc/init.d/autofs " + cond + "restart")
		return

# Fake the firstboot setup.
if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	textdomain("authconfig")
	gtk.glade.bindtextdomain("authconfig", "/usr/share/locale")
	module = childWindow()
	dialog = module.get_main_widget()
	if dialog.run() == gtk.RESPONSE_OK:
		module.apply()
	sys.exit(0)
