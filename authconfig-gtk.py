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
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import authinfo, acutil
import gettext, os, signal, sys
_ = gettext.lgettext
import locale
import dbus

locale.setlocale(locale.LC_ALL, '')

firstbootservices = [
	"autofs",
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
	os.execv('/usr/sbin/authconfig', ['authconfig']+sys.argv[1:])
	sys.exit(1)

try:
	import gtk, gtk.glade
except RuntimeError:
	sys.stderr.write(_("Unable to initialize graphical environment. Most likely cause of failure\n"
		"is that the tool was not run using a graphical environment. Please either\n"
		"start your graphical user interface or set your DISPLAY variable.\n"))
	sys.exit(2)

import msgarea

from dbus.mainloop.glib import DBusGMainLoop
DBusGMainLoop(set_as_default=True)

class Authconfig:
	def __init__(self):
		self.runPriority = 45
		self.moduleName = "Authentication"
		self.moduleClass = "reconfig"
		# "checkbox/button name": authInfo field, file, generic name,
		# package, function to call on checkbox activation
		self.main_map = {
			"enablesmartcard":
			("enableSmartcard", authinfo.PATH_PAM_PKCS11,
			 "Smartcard", "pam_pkcs11", self.display_smartcard_opts),
			"enablefprintd":
			("enableFprintd", authinfo.PATH_PAM_FPRINTD,
			 "Fprintd", "pam_fprintd", None),
			"enablepamaccess" :
			("enablePAMAccess", "", "", "", None),
			"passwordalgo" :
			("passwordAlgorithm", "", "", "",
			 ["DESCRYPT", "BIGCRYPT", "MD5", "SHA256", "SHA512"]),
			"enablemkhomedir" :
			("enableMkHomeDir", "", "", "", None),
                        "minlen" :
                        ("passMinLen", "", "", "", None),
                        "minclass" :
                        ("passMinClass", "", "", "", None),
                        "maxrepeat" :
                        ("passMaxRepeat", "", "", "", None),
                        "maxclassrepeat" :
                        ("passMaxClassRepeat", "", "", "", None),
                        "reqlower" :
                        ("passReqLower", "", "", "", None),
                        "requpper" :
                        ("passReqUpper", "", "", "", None),
                        "reqdigit" :
                        ("passReqDigit", "", "", "", None),
                        "reqother" :
                        ("passReqOther", "", "", "", None),
		}
		self.pass_keys = ("minlen", "minclass",
			 "maxrepeat", "maxclassrepeat",
			 "reqlower", "requpper", "reqdigit", "reqother")
		# "id type": localized name, tuple of allowed auth types,
		# option widget, option map name, file, package
		self.id_map = {
			"local":
			(_("Local accounts only"), ("local",),
			 "identitylabel", "empty_map", "", ""),
			"LDAP":
			(_("LDAP"), ("Kerberos", "LDAPAuth"),
			 "ldapoptions", "ldap_map", (authinfo.PATH_LIBNSS_LDAP, authinfo.PATH_LIBNSS_SSS), ("nss-pam-ldapd", "sssd-client")),
			"FreeIPA":
			(_("FreeIPA"), ("Kerberos",),
			 "ldapoptions", "ldap_map", (authinfo.PATH_LIBNSS_LDAP, authinfo.PATH_LIBNSS_SSS), ("nss-pam-ldapd", "sssd-client")),
			"NIS":
			(_("NIS"), ("NISAuth", "Kerberos"),
			 "nisoptions", "nis_map", authinfo.PATH_LIBNSS_NIS, "ypbind"),
			"Winbind":
			(_("Winbind"), ("WinbindAuth",),
			 "winbindoptions", "winbind_map", authinfo.PATH_WINBIND, "samba-winbind-clients"),
			"IPAv2":
			(_("IPAv2"), ("IPAv2Auth",),
			 "ipav2options", "ipav2_map", authinfo.PATH_IPA_CLIENT_INSTALL, "freeipa-client")
		}
		# to keep the order we need a tuple
		self.id_keys = ("local", "LDAP", "IPAv2", "FreeIPA", "NIS", "Winbind")
		# "auth type": localized name,
		# option widget, option map name, file, package
		self.auth_map = {
			"local":
			(_("Password"),
			 "authlabel", "empty_map", "", ""),
			"LDAPAuth":
			(_("LDAP password"),
			 "authlabel", "empty_map", "", ""),
			"Kerberos":
			(_("Kerberos password"),
			 "kerberosoptions", "kerberos_map", (authinfo.PATH_PAM_KRB5, authinfo.PATH_PAM_SSS), ("pam_krb5", "sssd-client")),
			"NISAuth":
			(_("NIS password"),
			 "authlabel", "empty_map", "", ""),
			"WinbindAuth":
			(_("Winbind password"),
			 "authlabel", "empty_map", "", ""),
			"IPAv2Auth":
			(_("IPAv2 password"),
			 "authlabel", "empty_map", "", ""),
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
			"nisdomain" : ("nisDomain", ""),
			"nisserver" : ("nisServer", ""),
		}
		self.kerberos_map = {
			"krbrealm" : ("kerberosRealm", ""),
			"kdc" : ("kerberosKDC", ""),
			"adminserver" : ("kerberosAdminServer", ""),
			"dnsrealm" : ("kerberosRealmviaDNS", "", "", "", self.kerberos_dns),
			"dnskdc" : ("kerberosKDCviaDNS", "", "", "", self.kerberos_dns),
		}
		self.ldap_map = {
			"ldaptls" : ("enableLDAPS", "", "", "", self.enable_cacert_download),
			"downloadcacert" : ("ldap_cacert_download", ""),
			"ldapbasedn" : ("ldapBaseDN", ""),
			"ldapserver" : ("ldapServer", "", "", "", self.enable_cacert_download),
		}
		self.ldapcacert_map = {
			"cacerturl" : ("ldapCacertURL", ""),
		}
		self.smartcard_map = {
			"scaction" : ("smartcardAction", authinfo.getSmartcardActions(),()),
			"forcesmartcard" : ("forceSmartcard", ""),
		}
		self.fprintd_map = {
		}
		self.winbindjoin_map = {
			"domain" : ("smbWorkgroup", ""),
			"joinuser" : ("joinUser", ""),
			"joinpassword" : ("joinPassword", ""),
		}
		self.winbind_map = {
			"winbinddomain" : ("smbWorkgroup", ""),
			"winbindsecurity" : ("smbSecurity", ("ads", "domain", "server", "user"),
				(("winbindrealm", ("ads",)),
				 ("winbindshell", ("domain", "ads")),
				 ("winbindjoin", ("domain", "ads")))),
			"winbindrealm" : ("smbRealm", ""),
			"winbindservers" : ("smbServers", ""),
			"winbindshell" : ("winbindTemplateShell",
				["/bin/false"] + acutil.getusershells(), ()),
			"winbindoffline" : ("winbindOffline", ""),
			"winbindjoin" : ("winbindjoin_maybe_launch", "")
		}
		self.ipav2join_map = {
			"domain" : ("ipav2Domain", ""),
			"joinuser" : ("joinUser", ""),
			"joinpassword" : ("joinPassword", ""),
		}
		self.ipav2_map = {
			"ipav2domain" : ("ipav2Domain", "", "", "", self.ipa_need_join),
			"ipav2realm" : ("ipav2Realm", "", "", "", self.ipa_need_join),
			"ipav2server" : ("ipav2Server", "", "", "", self.ipa_need_join),
			"ipav2nontp" : ("ipav2NoNTP", ""),
			"ipav2join" : ("ipav2join_maybe_launch", "")
		}
		self.info = authinfo.read(self.message_callback)
		self.pristineinfo = self.info.copy()
		if self.info.enableLocAuthorize == None:
			self.info.enableLocAuthorize = True # ON by default
		self.currid = self.current_idtype()
		self.currauth = self.current_authtype()
		if self.currauth not in self.id_map[self.currid][1]:
			self.currauth = self.id_map[self.currid][1][0]
		self.suspendchanges = False
		self.scxml = None
		self.msgctrl = None
		self.oldrealm = ""
		self.oldkdc = ""
		self.oldadminserver = ""

	def destroy_widget(self, button, widget):
		widget.destroy()

	def apply_settings(self, map, xml, parent):
		backup = self.info.copy()
		pristine = authinfo.read(self.message_callback)
		self.info_apply(map, xml)
		if self.info.differs(pristine):
			response = self.run_on_button(None, "joinsave",
						      "empty_map", parent,
						      (0, 1))
			if (response == gtk.RESPONSE_CANCEL):
				return None
			# Don't save.
			if (response == 0):
				self.info = backup
			# Save.
			if (response == 1):
				self.apply()
				backup = self.info
		return backup

	def winbindjoin_maybe_launch(self, button, map, xml, parent):
		backup = self.apply_settings(map, xml, parent)
		if not backup:
			return
		self.winbindjoin_launch(button, map, xml, parent)
		self.info = backup

	def winbindjoin_launch(self, button, map, xml, parent):
		if not self.info.joinUser:
			self.info.joinUser = "Administrator"
		response = self.run_on_button(None, "joinwbdomain",
					      "winbindjoin_map", parent)
		if (response == gtk.RESPONSE_OK):
			self.info.joinDomain(True)
		self.info.joinUser = None
		self.info.joinPassword = None

	def ipav2join_maybe_launch(self, button, map, xml, parent):
		backup = self.apply_settings(map, xml, parent)
		if not backup:
			return
		self.ipav2join_launch(button, map, xml, parent)
		self.info = backup

	def ipav2join_launch(self, button, map, xml, parent):
		response = self.run_on_button(None, "joinipadomain",
					      "ipav2join_map", parent)
		if (response == gtk.RESPONSE_OK):
			self.info.joinIPADomain(True)

	def info_apply(self, map, xml):
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.ComboBox()):
				setattr(self.info, map[entry][0],
					widget.get_data("option_list")[widget.get_active()])
			if type(widget) == type(gtk.Entry()) or type(widget) == type(gtk.SpinButton()):
				setattr(self.info, map[entry][0],
					widget.get_text())
			if type(widget) == type(gtk.CheckButton()):
				setattr(self.info, map[entry][0],
					widget.get_active())
		self.info.update()

	# Toggle a boolean.
	def toggleboolean(self, checkbox, name, trigger, xml):
		active = checkbox.get_active()
		setattr(self.info, name, active)
		if trigger:
			trigger(active, xml)

	# Run trigger on changed entry
	def changedentry(self, entry, name, trigger, xml):
		if trigger:
			trigger(entry.get_text(), xml)

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

        def entrychanged(self, widget, entry):
                setattr(self.info, entry[0], widget.get_text())

	def update_widgets(self, mapname, map, xml, topparent):
		self.info.update()
		if mapname == "smartcard_map":
			widget = xml.get_widget("scaction")
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
			if type(widget) == type(gtk.Button()):
				widget.connect("clicked",
					       getattr(self, map[entry][0]),
					       map,
					       xml,
					       topparent)
			if type(widget) == type(gtk.Entry()):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))
				if len(map[entry]) > 4:
					widget.connect("changed", self.changedentry,
						entry, map[entry][4], xml)
			if type(widget) == type(gtk.CheckButton()):
				boolval = bool(getattr(self.info, map[entry][0]))
				if (map[entry][0] == "kerberosRealmviaDNS" and
					self.info.kerberosRealmviaDNS == None):
						boolval = False
				elif (map[entry][0] == "kerberosKDCviaDNS" and
					self.info.kerberosKDCviaDNS == None):
						boolval = True
				widget.set_active(boolval)
				if len(map[entry]) > 4:
					widget.connect("toggled", self.toggleboolean,
						entry, map[entry][4], xml)
			if type(widget) == type(gtk.Label()):
				if getattr(self.info, map[entry][0]):
					widget.set_text(getattr(self.info,
								map[entry][0]))
		# now run all the triggers as the data is set
		for entry in map.keys():
			widget = xml.get_widget(entry)
			if type(widget) == type(gtk.ComboBox()):
				self.changeoption(widget, map[entry], xml)
			if type(widget) == type(gtk.Entry()):
				if len(map[entry]) > 4:
					self.changedentry(widget,
						entry, map[entry][4], xml)
			if type(widget) == type(gtk.CheckButton()):
				if len(map[entry]) > 4:
					self.toggleboolean(widget,
						entry, map[entry][4], xml)

	# Create a vbox or dialog using the file, and return it. */
	def run_on_button(self, button, top, mapname, parent=None, responses=()):
		xml = gtk.glade.XML(gladepath,
				    top, "authconfig")
		map = getattr(self, mapname)
		dialog = xml.get_widget(top)
		self.update_widgets(mapname, map, xml, dialog)
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

	def current_type(self, typemap):
		# skip local method as this is the default
		for meth in typemap.keys():
			if meth != 'local':
				try:
					if getattr(self.info, 'enable' + meth):
						if meth == 'LDAP' and self.info.ldapSchema == 'rfc2307bis':
							meth = 'FreeIPA'
						return meth
				except AttributeError:
					pass
		return 'local'

	def update_type(self, typemap, typevalue):
		if typevalue == 'FreeIPA':
			self.info.ldapSchema = 'rfc2307bis'
			typevalue = 'LDAP'
		elif typevalue == 'LDAP':
			# default is rfc2307
			self.info.ldapSchema = ''
		for meth in typemap.keys():
			if meth != 'local' and hasattr(self.info, 'enable' + meth):
				setattr(self.info, 'enable' + meth, meth == typevalue)

	def current_idtype(self):
		return self.current_type(self.id_map)

	def current_authtype(self):
		return self.current_type(self.auth_map)

	def display_opts(self, optname, sitename, mapname, topparent):
		optxml = gtk.glade.XML(gladepath,
				optname, "authconfig")

		opts = optxml.get_widget(optname)
		parent = opts.get_parent()
		if parent:
			parent.remove(opts)
		placement = self.xml.get_widget(sitename)
		placement.remove(placement.get_child())
		placement.add(opts)
		if mapname != "empty_map":
			self.update_widgets(mapname, getattr(self, mapname),
				optxml, topparent)
		return optxml

	def is_ldap_secure(self, xml):
		ldaptls = xml.get_widget('ldaptls')
		ldapserver = xml.get_widget('ldapserver')
		return bool(ldaptls.get_active() or
			'ldaps:' in ldapserver.get_text())

	#
	# if a 'fix' button is desired, use button_label and button_action
	# button_action is a function object.
	#
	def display_msgctrl(self, text, button_label=None, button_action=None):
		apply = self.xml.get_widget('apply')
		apply.set_sensitive(False)
		if self.msgctrl == None:
			self.msgctrl = msgarea.MsgAreaController()
			self.xml.get_widget('idauthpage').pack_start(self.msgctrl)
			self.xml.get_widget('idauthpage').reorder_child(self.msgctrl, 0)
		area = self.msgctrl.new_from_text_and_icon(gtk.STOCK_DIALOG_ERROR, text)

		# Create a "fix this" action button for the message
		if button_label:
			button = None
			def on_area_response(self, respid):
				if respid == gtk.RESPONSE_YES:
					button_action()
			button = area.add_button(button_label, gtk.RESPONSE_YES)
			area.connect("response", on_area_response)

		self.xml.get_widget('idauthpage').show_all()
		apply.set_tooltip_markup("<span color='dark red'>%s</span>" % text)

	def clear_msgctrl(self):
		apply = self.xml.get_widget('apply')
		apply.set_sensitive(True)
		if self.msgctrl != None:
			self.msgctrl.clear()
			apply.set_tooltip_markup(None)

	def is_ldap_URI_valid(self, xml):
		ldapserver = xml.get_widget('ldapserver')
		uritovalidate = ldapserver.get_text()
		return self.info.validateLDAPURI(uritovalidate)

	def enable_cacert_download(self, active, xml):
		ldapurivalid = self.is_ldap_URI_valid(xml)
		downloadcacert = xml.get_widget('downloadcacert')
		if downloadcacert:
			secureldap = self.is_ldap_secure(xml)
			downloadcacert.set_sensitive(secureldap)
			secureldap = secureldap or self.currauth != "LDAPAuth"
		else:
			secureldap = True
		if secureldap and ldapurivalid:
			self.clear_msgctrl()
		elif not ldapurivalid:
			text = _("Invalid LDAP URI.")
			self.display_msgctrl(text)
		else:
			text = _("You must provide ldaps:// server address or use TLS for LDAP authentication.")
			self.display_msgctrl(text)

	def ipa_need_join(self, active, xml):
		if self.currid != "IPAv2" or self.info.ipaDomainJoined:
			self.clear_msgctrl()
		else:
			text = _("Use the \"Join Domain\" button to join the IPAv2 domain.")
			self.display_msgctrl(text)

	def install_package(self, package):
		parent=self.xml.get_widget('authconfig')

		try:
			bus = dbus.SessionBus()
			proxy = bus.get_object('org.freedesktop.PackageKit', '/org/freedesktop/PackageKit')
			iface = dbus.Interface(proxy, 'org.freedesktop.PackageKit.Modify')
			iface.InstallPackageNames(dbus.UInt32(parent.window.xid), [package],
			                          "show-confirm-search, show-confirm-deps, hide-finished")
		except dbus.DBusException, e:
			self.display_msgctrl("Failure using package kit: %s" % str(e))
		self.missing_packages()

	def missing_package(self, path, service, package):
		if type(path) == tuple:
			if self.info.sssdSupported():
				path = path[1]
				package = package[1]
			else:
				path = path[0]
				package = package[0]
		try:
			if path:
				os.stat(path)
			self.clear_msgctrl()
		except:
			text = _("The %s file was not found, but it is required for %s support to work properly.\nInstall the %s package, which provides this file.")
			self.display_msgctrl(text % (path, service, package),
			                     button_label="Install",
			                     button_action=lambda:self.install_package(package))
			return True
		return False

	def missing_packages(self):
		return (self.missing_package(self.id_map[self.currid][4],
				self.id_map[self.currid][0], self.id_map[self.currid][5]) or
			self.missing_package(self.auth_map[self.currauth][3],
				self.auth_map[self.currauth][0], self.auth_map[self.currauth][4]))

	def kerberos_dns(self, active, xml):
		dnsrealm = xml.get_widget('dnsrealm').get_active()
		dnskdc = xml.get_widget('dnskdc').get_active()
		krbrealm = xml.get_widget('krbrealm')
		if dnsrealm:
			if krbrealm.get_property("sensitive"):
				self.oldrealm = krbrealm.get_text()
			krbrealm.set_text("")
		elif self.oldrealm:
			krbrealm.set_text(self.oldrealm)
		krbrealm.set_sensitive(not dnsrealm)
		kdc = xml.get_widget('kdc')
		adminserver = xml.get_widget('adminserver')
		if dnskdc:
			if kdc.get_property("sensitive"):
				self.oldkdc = kdc.get_text()
			if adminserver.get_property("sensitive"):
				self.oldadminserver = adminserver.get_text()
			kdc.set_text("")
			adminserver.set_text("")
		else:
			if self.oldkdc:
				kdc.set_text(self.oldkdc)
			if self.oldadminserver:
				adminserver.set_text(self.oldadminserver)
		kdc.set_sensitive(not dnskdc)
		adminserver.set_sensitive(not dnskdc)

	def display_smartcard_opts(self, active, xml):
		if self.scxml:
			self.info_apply(self.smartcard_map, self.scxml)
		if active:
			self.scxml = self.display_opts('smartcardoptions',
				'scauthsite', 'smartcard_map', None)
		else:
			self.scxml = None
			self.display_opts('scauthlabel', 'scauthsite',
				'empty_map', None)

	def clear_combo(self, widget):
		for i in range(0, len(widget.get_model())):
			widget.remove_text(0)

	def set_combo(self, widget, choices, textmap, current):
		self.suspendchanges = True
		self.clear_combo(widget)
		offset = 0
		for entry in choices:
			widget.append_text(textmap[entry][0])
			if entry == current:
				widget.set_active(offset)
			offset += 1
		if offset <= 1:
			widget.set_sensitive(False)
		else:
			widget.set_sensitive(True)
		self.suspendchanges = False


	def apply_idsettings(self):
		mapname = self.id_map[self.currid][3]
		if mapname != "empty_map":
			self.info_apply(getattr(self, mapname), self.idxml)

	def apply_authsettings(self):
		mapname = self.auth_map[self.currauth][2]
		if mapname != "empty_map":
			self.info_apply(getattr(self, mapname), self.authxml)

	def apply_passsettings(self):
		passmap = {}
		for k, v in self.main_map.iteritems():
			if k in self.pass_keys:
				passmap[k] = v
		self.info_apply(passmap, self.xml)

	def display_idopts(self, topparent):
		self.idxml = self.display_opts(self.id_map[self.currid][2], 'identitysite',
			self.id_map[self.currid][3], topparent)

	def idcombochanged(self, combo, authcombo, topparent):
		if self.suspendchanges:
			return
		self.apply_idsettings()
		self.currid = self.id_keys[combo.get_active()]
		self.display_idopts(topparent)
		displayopts = False
		if self.currauth not in self.id_map[self.currid][1]:
			self.apply_authsettings()
			self.currauth = self.id_map[self.currid][1][0]
			displayopts = True
		self.set_combo(authcombo, self.id_map[self.currid][1], self.auth_map,
				self.currauth)
		if displayopts:
			self.display_authopts(topparent)
		self.update_type(self.id_map, self.currid)
		self.update_type(self.auth_map, self.currauth)
		if not self.missing_packages():
			self.enable_cacert_download(None, self.idxml)
			self.ipa_need_join(None, self.idxml)

	def display_authopts(self, topparent):
		self.authxml = self.display_opts(self.auth_map[self.currauth][1], 'authsite',
			self.auth_map[self.currauth][2], topparent)

	def authcombochanged(self, combo, topparent):
		if self.suspendchanges:
			return
		self.apply_authsettings()
		self.currauth = self.id_map[self.currid][1][combo.get_active()]
		self.display_authopts(topparent)
		self.update_type(self.auth_map, self.currauth)
		if not self.missing_packages():
			self.enable_cacert_download(None, self.idxml)
			self.ipa_need_join(None, self.idxml)

	# Create a vbox with the right controls and return the vbox.
	def get_main_widget(self, xml):
		self.xml = xml
		dialog = xml.get_widget('authconfig')
		# Set main comboboxes
		idcombo = xml.get_widget('identitytype')
		self.set_combo(idcombo, self.id_keys, self.id_map, self.currid)
		authcombo = xml.get_widget('authtype')
		self.set_combo(authcombo, self.id_map[self.currid][1], self.auth_map,
				self.currauth)

		# display options
		self.display_idopts(dialog)
		self.display_authopts(dialog)

		idcombo.connect("changed", self.idcombochanged, authcombo, dialog)
		authcombo.connect("changed", self.authcombochanged, dialog)

		# Hook up checkboxes and entry fields.
		for entry in self.main_map.keys():
			widget = xml.get_widget(entry)
       			try:
               			if self.main_map[entry][1]:
       					os.stat(self.main_map[entry][1])
       			except:
       				widget.set_sensitive(False)
       			else:
                                if type(widget) == type(gtk.CheckButton()):
        				widget.set_active(bool(getattr(self.info,
						  self.main_map[entry][0])))
			if type(widget) == type(gtk.CheckButton()):
				widget.connect("toggled", self.toggleboolean,
					       self.main_map[entry][0],
					       self.main_map[entry][4], xml)
				self.toggleboolean(widget,
						   self.main_map[entry][0],
						   self.main_map[entry][4], xml)
			elif type(widget) == type(gtk.ComboBox()):
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
                        elif type(widget) == type(gtk.SpinButton()):
 				if getattr(self.info, self.main_map[entry][0]):
                                        try:
        					widget.set_value(float(getattr(self.info,
							self.main_map[entry][0])))
                                        except ValueError:
                                                pass
				widget.connect("changed", self.entrychanged,
					       self.main_map[entry])
                               
			# if no tokens are installed, don't enable smartcard
			# login
			if entry == "enablesmartcard" and len(authinfo.getSmartcardModules()) == 0:
				widget.set_sensitive(False)
		return dialog

	# Save changes.
	def apply(self):
		self.update_type(self.id_map, self.currid)
		self.update_type(self.auth_map, self.currauth)
		self.apply_idsettings()
		self.apply_authsettings()
		self.apply_passsettings()
		if self.scxml:
			self.info_apply(self.smartcard_map, self.scxml)
		self.info.testLDAPCACerts()
		self.info.rehashLDAPCACerts()

		if "--updateall" in sys.argv:
			self.info.write()
		else:
			self.info.writeChanged(self.pristineinfo)

		self.info.post(False)
		if "--firstboot" in sys.argv:
			for service in firstbootservices:
				if authinfo.Service.isEnabled(service):
					authinfo.Service.tryRestart(service)

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
	gladepath = os.path.dirname(authinfo.__file__)+"/authconfig.glade"
	if not os.access(gladepath, os.R_OK):
		gladepath = "/usr/share/authconfig/authconfig.glade"
	gtk.window_set_default_icon_name("system-config-authentication")
	ret = -1
	while ret == -1:
		module = Authconfig()
		xml = gtk.glade.XML(gladepath,
			    'authconfig', "authconfig")
		dialog = module.get_main_widget(xml)

		while True:
			response = dialog.run()
			if response == 1:
				if module.run_on_button(None, "revertsettings",
					"empty_map", dialog) == gtk.RESPONSE_OK:
					module.info.restoreLast()
					break
			else:
				break

		if response == gtk.RESPONSE_OK:
			module.apply()
			ret = 0
		elif response != 1:
			ret = 1
		dialog.destroy()
	sys.exit(ret)
