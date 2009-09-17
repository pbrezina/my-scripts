#!/usr/bin/python
# -*- coding: UTF-8 -*-
#
# Authconfig - client authentication configuration program
# Copyright (c) 1999-2008 Red Hat, Inc.
#
# Authors: Preston Brown <pbrown@redhat.com>
#          Nalin Dahyabhai <nalin@redhat.com>
#          Matt Wilson <msw@redhat.com>
#          Tomas Mraz <tmraz@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
import authinfo, acutil
import gettext, os, signal, sys
_ = gettext.lgettext
import locale
locale.setlocale(locale.LC_ALL, '')

firstbootservices = [
	"crond",
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
	sys.argv.remove('--nox')
	os.execv('/usr/bin/authconfig', ['authconfig']+sys.argv[1:])
	sys.exit(1)

try:
	import gtk, gtk.glade
except RuntimeError, e:
	if (os.isatty(sys.stdin.fileno()) and
	    os.isatty(sys.stdout.fileno()) and
	    os.isatty(sys.stderr.fileno())):
		os.execv('/usr/bin/authconfig', ['authconfig']+sys.argv[1:])
		sys.exit(1)
	else:
		raise e

class Authconfig:
	def __init__(self):
		self.runPriority = 45
		self.moduleName = "Authentication"
		self.moduleClass = "reconfig"
		# "checkbox/button name": authInfo field, file, generic name,
		# package, names of widgets to disable if checkbox not active
		self.main_map = {
			"enablecache" :
			("enableCache", authinfo.PATH_NSCD,
			 "caching", "nscd", []),
			"enablenis" :
			("enableNIS", authinfo.PATH_YPBIND,
			 "NIS", "ypbind", ["confignis"]),
			"enablehesiod" :
			("enableHesiod", authinfo.PATH_LIBNSS_HESIOD,
			 "Hesiod", "glibc", ["confighesiod"]),
			"enableldap" :
			("enableLDAP", authinfo.PATH_LIBNSS_LDAP,
			 "LDAP", "nss_ldap", ["configldap"]),
			"enableldapauth" :
			("enableLDAPAuth", authinfo.PATH_PAM_LDAP,
			 "LDAP", "nss_ldap", ["configldapauth"]),
			"enablekerberos" :
			("enableKerberos", authinfo.PATH_PAM_KRB5,
			 "Kerberos", "pam_krb5", ["configkerberos"]),
			"enablesmartcard":
			("enableSmartcard", authinfo.PATH_PAM_PKCS11,
			 "Smartcard", "pam_pkcs11", ["configsmartcard"]),
			"enablefprintd":
			("enableFprintd", authinfo.PATH_PAM_FPRINTD,
			 "Fprintd", "pam_fprintd", []),
			"enableshadow" :
			("enableShadow", "", "", "", []),
			"enablewinbind" :
			("enableWinbind", authinfo.PATH_LIBNSS_WINBIND,
			 "winbind", "samba-client", ["configwinbind"]),
			"enablewinbindauth" :
			("enableWinbindAuth", authinfo.PATH_PAM_WINBIND,
			 "winbind", "samba-client", ["configwinbindauth"]),
			"enablelocauthorize" :
			("enableLocAuthorize", "", "", "", []),
			"enablepamaccess" :
			("enablePAMAccess", "", "", "", []),
			"enablesysnetauth" :
			("enableSysNetAuth", "", "", "", []),
			"passwordalgo" :
			("passwordAlgorithm", "", "", "",
			 ["DESCRYPT", "BIGCRYPT", "MD5", "SHA256", "SHA512"]),
			"enablemkhomedir" :
			("enableMkHomeDir", "", "", "", []),
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
			"tls" : ("enableLDAPS", "", "", "", "downloadcacert"),
			"downloadcacert" : ("ldap_cacert_download", ""),
			"basedn" : ("ldapBaseDN", ""),
			"server" : ("ldapServer", ""),
		}
		self.ldapcacert_map = {
			"cacerturl" : ("ldapCacertURL", ""),
		}
		self.smartcard_map = {
			"module" : ("smartcardModule", authinfo.getSmartcardModules(),()),
			"action" : ("smartcardAction", authinfo.getSmartcardActions(),()),
			"forcesmartcard" : ("forceSmartcard", ""),
		}
		self.fprintd_map = {
		}
		self.hesiod_map = {
			"lhs" : ("hesiodLHS", ""),
			"rhs" : ("hesiodRHS", ""),
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
			"shell" : ("winbindTemplateShell", ["/bin/false"] + acutil.getusershells(), ()),
			"offline" : ("winbindOffline", ""),
			"join" : ("winbindjoin_maybe_launch", "")
		}
		self.launch_map = {
			"confignis": ("nissettings", "nis_map"),
			"configldap": ("ldapsettings", "ldap_map"),
			"configldapauth": ("ldapsettings", "ldap_map"),
			"confighesiod": ("hesiodsettings", "hesiod_map"),
			"configkerberos": ("kerberossettings", "kerberos_map"),
			"configsmartcard": ("smartcardsettings", "smartcard_map"),
			"configwinbind": ("winbindsettings", "winbind_map"),
			"configwinbindauth": ("winbindsettings", "winbind_map"),
		}
		self.info = authinfo.read(self.message_callback)
		self.pristineinfo = self.info.copy()
		if self.info.enableLocAuthorize == None:
			self.info.enableLocAuthorize = True # ON by default
		return

	def destroy_widget(self, button, widget):
		widget.destroy()
		return

	def winbindjoin_maybe_launch(self, button, map, xml, parent):
		backup = self.info.copy()
		pristine = authinfo.read(self.message_callback)
		self.info_apply(map, xml)
		if self.info.differs(pristine):
			response = self.run_on_button(None, "joinsave",
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
		response = self.run_on_button(None, "winbindjoin",
					      "winbindjoin_map", parent)
		if (response == gtk.RESPONSE_OK):
			self.info.joinDomain(True)
		self.info.joinUser = None
		self.info.joinPassword = None

	def info_apply(self, map, xml):
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.ComboBox()):
				setattr(self.info, map[entry][0],
					widget.get_data("option_list")[widget.get_active()])
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

	def changeoption(self, combo, entry, xml):
	        options = combo.get_data("option_list")
		option = options[combo.get_active()]
		for candidate in entry[2]:
			dependent = xml.get_widget(candidate[0])
			if option in candidate[1]:
				dependent.set_sensitive(True)
			else:
				dependent.set_sensitive(False)

	def combochanged(self, combo, entry):
		option = entry[4][combo.get_active()]
		setattr(self.info, entry[0], option)

	# Create a vbox or dialog using the file, and return it. */
	def run_on_button(self, button, top, mapname, parent=None, responses=()):
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				    top, "authconfig")
		map = getattr(self, mapname)
		dialog = xml.get_widget(top)
		self.info.update()
		if mapname == "smartcard_map":
			widget = xml.get_widget("action")
			if not os.access("/usr/bin/gnome-screensaver", os.X_OK):
				widget.set_sensitive(False)
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.ComboBox()):
				widget.remove_text(0) # remove the bogus text necessary for glade
				options = []
				offset = 0
				for option in tuple(map[entry][1]):
					if option == '':
						continue
					widget.append_text(option)
					options.append(option)
					if option == getattr(self.info, map[entry][0]):
						widget.set_active(offset)
					offset = offset + 1
				option = getattr(self.info, map[entry][0])
				if option not in options:
					if option:
						widget.prepend_text(option)
						widget.set_active(0)
						options.insert(0, option)
				widget.set_data("option_list", options)
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
				widget.set_active(bool(getattr(self.info,
							  map[entry][0])))
				if len(map[entry]) > 4:
					button = xml.get_widget(map[entry][4])
					widget.connect("toggled", self.toggleboolean,
						entry, [], [button])
					self.toggleboolean(widget,
						entry, [], [button])
			if type(widget) == type(gtk.Label()):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))
		if parent:
			dialog.set_transient_for(parent)
			parent.set_sensitive(False)
		dialog.set_resizable(False)
		response = None
		while ((response != gtk.RESPONSE_OK) and
		       (response != gtk.RESPONSE_CANCEL) and
		       (response not in responses)):
			response = dialog.run()
		if (response == gtk.RESPONSE_OK):
			self.info_apply(map, xml)
			if (mapname == "ldap_map"):
			    self.ldap_cacerts_test(parent)
		dialog.destroy()
		if parent:
			parent.set_sensitive(True)
		return response

	# Create a vbox with the right controls and return the vbox.
	def get_main_widget(self):
		xml = gtk.glade.XML("/usr/share/authconfig/authconfig.glade",
				'authconfig', "authconfig")
		dialog = xml.get_widget('authconfig')

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
			try:
				if self.main_map[entry][1]:
					os.stat(self.main_map[entry][1])
			except:
				widget.set_sensitive(False)
			else:
				widget.set_active(bool(getattr(self.info,
						  self.main_map[entry][0])))
			if type(widget) == type(gtk.CheckButton()):
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
			if type(widget) == type(gtk.ComboBox()):
				widget.remove_text(0) # remove the bogus text necessary for glade
				options = self.main_map[entry][4]
				offset = 0
				current = getattr(self.info, self.main_map[entry][0]).upper()
				for option in options:
					widget.append_text(option)
					if option == current:
						widget.set_active(offset)
					offset = offset + 1
				if current and current not in options:
					widget.prepend_text(option)
					widget.set_active(0)
					options.insert(0, option)
				widget.connect("changed", self.combochanged,
					       self.main_map[entry])
			# if not tokens are installed, don't enable smartcard
			# login
			if entry == "enablesmartcard" and len(authinfo.getSmartcardModules()) == 0:
				widget.set_sensitive(False)
		return dialog

	# Save changes.
	def apply(self, button = None):
		self.info.testLDAPCACerts()
		self.info.rehashLDAPCACerts()
		if "--updateall" in sys.argv:
			self.info.write()
		else:
			self.info.writeChanged(self.pristineinfo)
		self.info.post(False)
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

	def ldap_cacerts_test(self, parent):
		if self.info.enableLDAPS and self.info.testLDAPCACerts():
		    self.ldap_cacert_download(None, None, None, parent)

	def ldap_cacert_download(self, button, map, xml, parent):
		response = self.run_on_button(None, "ldapcacertdownload",
					      "ldapcacert_map", parent)
		if (response == gtk.RESPONSE_OK):
			self.info.downloadLDAPCACert()

	def message_callback(self, text):
		msg = gtk.MessageDialog(None, 0, gtk.MESSAGE_WARNING, gtk.BUTTONS_OK, text)
		msg.set_title(_("Authentication Configuration"))
		msg.run()
		msg.destroy()

# Fake the firstboot setup.
if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	gettext.textdomain("authconfig")
	gtk.glade.bindtextdomain("authconfig", "/usr/share/locale")
	module = Authconfig()
	dialog = module.get_main_widget()
	while True:
		response = dialog.run()
		if response == gtk.RESPONSE_OK:
			module.apply()
			dialog.destroy()
			sys.exit(0)
		elif response == 1:
			response = module.run_on_button(None, "revertsettings",
				"empty_map", dialog)
			if (response == gtk.RESPONSE_OK):
				module.info.restoreLast()
				# reload module
				dialog.destroy()
				module = Authconfig()
				dialog = module.get_main_widget()
		else:
			dialog.destroy()
			sys.exit(1)

