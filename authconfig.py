#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
# Authconfig - client authentication configuration program
# Copyright (c) 1999-2014 Red Hat, Inc.
#
# Original authors: Preston Brown <pbrown@redhat.com>
#                   Nalin Dahyabhai <nalin@redhat.com>
#                   Matt Wilson <msw@redhat.com>
# Python rewrite and further development by: Tomas Mraz <tmraz@redhat.com>
# Additional authors: Jan Lieskovsky <jlieskov@redhat.com>
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
_ = gettext.gettext
from optparse import OptionParser, IndentedHelpFormatter
import locale

try:
	locale.setlocale(locale.LC_ALL, '')
except locale.Error:
	sys.stderr.write('Warning: Unsupported locale setting.\n')

class UnihelpOptionParser(OptionParser):
	def print_help(self, file=None):
		if file is None:
			file = sys.stdout
		srcencoding = locale.getpreferredencoding()
		encoding = getattr(file, "encoding", None)
		if not encoding or encoding == "ascii":
			encoding = srcencoding
		if sys.version_info[0] < 3:
			file.write(self.format_help().decode(srcencoding).encode(encoding, "replace"))
		else:
			if 'b' in file.mode:
				file.write(self.format_help().encode(encoding, "replace"))
			else:
				file.write(self.format_help())

class NonWrapFormatter(IndentedHelpFormatter):
	def format_option(self, option):
	        # The help for each option consists of two parts:
	        #   * the opt strings and metavars
	        #     eg. ("-x", or "-fFILENAME, --file=FILENAME")
	        #   * the user-supplied help string
	        #     eg. ("turn on expert mode", "read data from FILENAME")
	        #
	        # If possible, we write both of these on the same line:
	        #   -x      turn on expert mode
	        #
	        # But if the opt string list is too long, we put the help
	        # string on a second line, indented to the same column it would
	        # start in if it fit on the first line.
	        #   -fFILENAME, --file=FILENAME
	        #           read data from FILENAME
		# We cannot wrap the help text as it can be in any language and
                # encoding and so we do not know how to wrap it correctly.
	        result = []
	        opts = self.option_strings[option]
	        opt_width = self.help_position - self.current_indent - 2
	        if len(opts) > opt_width:
	            opts = "%*s%s\n" % (self.current_indent, "", opts)
	            indent_first = self.help_position
	        else:                       # start help on same line as opts
	            opts = "%*s%-*s  " % (self.current_indent, "", opt_width, opts)
	            opts = "%*s%-*s  " % (self.current_indent, "", opt_width, opts)
	            indent_first = 0
	        result.append(opts)
	        if option.help:
	            help_text = self.expand_default(option)
	            result.append("%*s%s\n" % (indent_first, "", help_text))
	        elif opts[-1] != "\n":
	            result.append("\n")
	        return "".join(result)

class Authconfig:
	def __init__(self):
		self.nis_avail = False
		self.kerberos_avail = False
		self.ldap_avail = False
		self.sssd_avail = False
		self.cache_avail = False
		self.fprintd_avail = False
		self.retval = 0

	def module(self):
		return "authconfig"

	def printError(self, error):
		sys.stderr.write("%s: %s\n" % (self.module(), error))

	def listHelp(self, l, addidx):
		idx = 0
		help = "<"
		for item in l:
			if idx > 0:
				help += "|"
			if addidx:
				help += str(idx) + "="
			help += item
			idx += 1
		help += ">"
		return help

	def parseOptions(self):
		usage = _("usage: %s [options]") % self.module()
		if self.module() == "authconfig":
			usage += " {--update|--updateall|--test|--probe|--restorebackup <name>|--savebackup <name>|--restorelastbackup}"

		parser = UnihelpOptionParser(usage, add_help_option=False, formatter=NonWrapFormatter())
		parser.add_option("-h", "--help", action="help",
			help=_("show this help message and exit"))

		parser.add_option("--enableshadow", "--useshadow", action="store_true",
			help=_("enable shadowed passwords by default"))
		parser.add_option("--disableshadow", action="store_true",
			help=_("disable shadowed passwords by default"))
		parser.add_option("--enablemd5", "--usemd5", action="store_true",
			help=_("enable MD5 passwords by default"))
		parser.add_option("--disablemd5", action="store_true",
			help=_("disable MD5 passwords by default"))
		parser.add_option("--passalgo",
			metavar=self.listHelp(authinfo.password_algorithms, False),
			help=_("hash/crypt algorithm for new passwords"))

		parser.add_option("--enablenis", action="store_true",
			help=_("enable NIS for user information by default"))
		parser.add_option("--disablenis", action="store_true",
			help=_("disable NIS for user information by default"))
		parser.add_option("--nisdomain", metavar=_("<domain>"),
			help=_("default NIS domain"))
		parser.add_option("--nisserver", metavar=_("<server>"),
			help=_("default NIS server"))

		parser.add_option("--enableldap", action="store_true",
			help=_("enable LDAP for user information by default"))
		parser.add_option("--disableldap", action="store_true",
			help=_("disable LDAP for user information by default"))
		parser.add_option("--enableldapauth", action="store_true",
			help=_("enable LDAP for authentication by default"))
		parser.add_option("--disableldapauth", action="store_true",
			help=_("disable LDAP for authentication by default"))
		parser.add_option("--ldapserver", metavar=_("<server>"),
			help=_("default LDAP server hostname or URI"))
		parser.add_option("--ldapbasedn", metavar=_("<dn>"),
			help=_("default LDAP base DN"))
		parser.add_option("--enableldaptls", "--enableldapstarttls", action="store_true",
			help=_("enable use of TLS with LDAP (RFC-2830)"))
		parser.add_option("--disableldaptls",  "--disableldapstarttls", action="store_true",
			help=_("disable use of TLS with LDAP (RFC-2830)"))
		parser.add_option("--enablerfc2307bis", action="store_true",
			help=_("enable use of RFC-2307bis schema for LDAP user information lookups"))
		parser.add_option("--disablerfc2307bis", action="store_true",
			help=_("disable use of RFC-2307bis schema for LDAP user information lookups"))
		parser.add_option("--ldaploadcacert", metavar=_("<URL>"),
			help=_("load CA certificate from the URL"))

		parser.add_option("--enablesmartcard", action="store_true",
			help=_("enable authentication with smart card by default"))
		parser.add_option("--disablesmartcard", action="store_true",
			help=_("disable authentication with smart card by default"))
		parser.add_option("--enablerequiresmartcard", action="store_true",
			help=_("require smart card for authentication by default"))
		parser.add_option("--disablerequiresmartcard", action="store_true",
			help=_("do not require smart card for authentication by default"))
		parser.add_option("--smartcardmodule", metavar=_("<module>"),
			help=_("default smart card module to use"))
		actshelp = self.listHelp(authinfo.getSmartcardActions(), True)
		parser.add_option("--smartcardaction", metavar=actshelp,
			help=_("action to be taken on smart card removal"))

		parser.add_option("--enablefingerprint", action="store_true",
			help=_("enable authentication with fingerprint readers by default"))
		parser.add_option("--disablefingerprint", action="store_true",
			help=_("disable authentication with fingerprint readers by default"))

		parser.add_option("--enableecryptfs", action="store_true",
			help=_("enable automatic per-user ecryptfs"))
		parser.add_option("--disableecryptfs", action="store_true",
			help=_("disable automatic per-user ecryptfs"))

		parser.add_option("--enablekrb5", action="store_true",
			help=_("enable kerberos authentication by default"))
		parser.add_option("--disablekrb5", action="store_true",
			help=_("disable kerberos authentication by default"))
		parser.add_option("--krb5kdc", metavar=_("<server>"),
			help=_("default kerberos KDC"))
		parser.add_option("--krb5adminserver", metavar=_("<server>"),
			help=_("default kerberos admin server"))
		parser.add_option("--krb5realm", metavar=_("<realm>"),
			help=_("default kerberos realm"))
		parser.add_option("--enablekrb5kdcdns", action="store_true",
			help=_("enable use of DNS to find kerberos KDCs"))
		parser.add_option("--disablekrb5kdcdns", action="store_true",
			help=_("disable use of DNS to find kerberos KDCs"))
		parser.add_option("--enablekrb5realmdns", action="store_true",
			help=_("enable use of DNS to find kerberos realms"))
		parser.add_option("--disablekrb5realmdns", action="store_true",
			help=_("disable use of DNS to find kerberos realms"))

		parser.add_option("--enablewinbind", action="store_true",
			help=_("enable winbind for user information by default"))
		parser.add_option("--disablewinbind", action="store_true",
			help=_("disable winbind for user information by default"))
		parser.add_option("--enablewinbindauth", action="store_true",
			help=_("enable winbind for authentication by default"))
		parser.add_option("--disablewinbindauth", action="store_true",
			help=_("disable winbind for authentication by default"))
		parser.add_option("--smbsecurity", metavar="<user|server|domain|ads>",
			help=_("security mode to use for samba and winbind"))
		parser.add_option("--smbrealm", metavar=_("<realm>"),
			help=_("default realm for samba and winbind when security=ads"))
		parser.add_option("--smbservers", metavar=_("<servers>"),
			help=_("names of servers to authenticate against"))
		parser.add_option("--smbworkgroup", metavar=_("<workgroup>"),
			help=_("workgroup authentication servers are in"))
		parser.add_option("--smbidmaprange", "--smbidmapuid", "--smbidmapgid", metavar=_("<lowest-highest>"),
			help=_("uid range winbind will assign to domain or ads users"))
		parser.add_option("--winbindseparator", metavar="<\\>",
			help=_("the character which will be used to separate the domain and user part of winbind-created user names if winbindusedefaultdomain is not enabled"))
		parser.add_option("--winbindtemplatehomedir", metavar="</home/%D/%U>",
			help=_("the directory which winbind-created users will have as home directories"))
		parser.add_option("--winbindtemplateshell", metavar="</bin/false>",
			help=_("the shell which winbind-created users will have as their login shell"))
		parser.add_option("--enablewinbindusedefaultdomain", action="store_true",
			help=_("configures winbind to assume that users with no domain in their user names are domain users"))
		parser.add_option("--disablewinbindusedefaultdomain", action="store_true",
			help=_("configures winbind to assume that users with no domain in their user names are not domain users"))
		parser.add_option("--enablewinbindoffline", action="store_true",
			help=_("configures winbind to allow offline login"))
		parser.add_option("--disablewinbindoffline", action="store_true",
			help=_("configures winbind to prevent offline login"))
		parser.add_option("--enablewinbindkrb5", action="store_true",
			help=_("winbind will use Kerberos 5 to authenticate"))
		parser.add_option("--disablewinbindkrb5", action="store_true",
			help=_("winbind will use the default authentication method"))
		parser.add_option("--winbindjoin", metavar="<Administrator>",
			help=_("join the winbind domain or ads realm now as this administrator"))

		parser.add_option("--enablepreferdns", action="store_true",
			help=_("prefer dns over nis for hostname resolution"))
		parser.add_option("--disablepreferdns", action="store_true",
			help=_("do not prefer dns over nis for hostname resolution"))

		parser.add_option("--enablesssd", action="store_true",
			help=_("enable SSSD for user information by default with manually managed configuration"))
		parser.add_option("--disablesssd", action="store_true",
			help=_("disable SSSD for user information by default (still used for supported configurations)"))
		parser.add_option("--enablesssdauth", action="store_true",
			help=_("enable SSSD for authentication by default with manually managed configuration"))
		parser.add_option("--disablesssdauth", action="store_true",
			help=_("disable SSSD for authentication by default (still used for supported configurations)"))
		parser.add_option("--enableforcelegacy", action="store_true",
			help=_("never use SSSD implicitly even for supported configurations"))
		parser.add_option("--disableforcelegacy", action="store_true",
			help=_("use SSSD implicitly if it supports the configuration"))

		parser.add_option("--enablecachecreds", action="store_true",
			help=_("enable caching of user credentials in SSSD by default"))
		parser.add_option("--disablecachecreds", action="store_true",
			help=_("disable caching of user credentials in SSSD by default"))

		parser.add_option("--enablecache", action="store_true",
			help=_("enable caching of user information by default (automatically disabled when SSSD is used)"))
		parser.add_option("--disablecache", action="store_true",
			help=_("disable caching of user information by default"))

		parser.add_option("--enablelocauthorize", action="store_true",
			help=_("local authorization is sufficient for local users"))
		parser.add_option("--disablelocauthorize", action="store_true",
			help=_("authorize local users also through remote service"))

		parser.add_option("--enablepamaccess", action="store_true",
			help=_("check access.conf during account authorization"))
		parser.add_option("--disablepamaccess", action="store_true",
			help=_("do not check access.conf during account authorization"))

		parser.add_option("--enablesysnetauth", action="store_true",
			help=_("authenticate system accounts by network services"))
		parser.add_option("--disablesysnetauth", action="store_true",
			help=_("authenticate system accounts by local files only"))

		parser.add_option("--enablemkhomedir", action="store_true",
			help=_("create home directories for users on their first login"))
		parser.add_option("--disablemkhomedir", action="store_true",
			help=_("do not create home directories for users on their first login"))

		parser.add_option("--passminlen", metavar=_("<number>"),
			help=_("minimum length of a password"))
		parser.add_option("--passminclass", metavar=_("<number>"),
			help=_("minimum number of character classes in a password"))
		parser.add_option("--passmaxrepeat", metavar=_("<number>"),
			help=_("maximum number of same consecutive characters in a password"))
		parser.add_option("--passmaxclassrepeat", metavar=_("<number>"),
			help=_("maximum number of consecutive characters of same class in a password"))
		parser.add_option("--enablereqlower", action="store_true",
			help=_("require at least one lowercase character in a password"))
		parser.add_option("--disablereqlower", action="store_true",
			help=_("do not require lowercase characters in a password"))
		parser.add_option("--enablerequpper", action="store_true",
			help=_("require at least one uppercase character in a password"))
		parser.add_option("--disablerequpper", action="store_true",
			help=_("do not require uppercase characters in a password"))
		parser.add_option("--enablereqdigit", action="store_true",
			help=_("require at least one digit in a password"))
		parser.add_option("--disablereqdigit", action="store_true",
			help=_("do not require digits in a password"))
		parser.add_option("--enablereqother", action="store_true",
			help=_("require at least one other character in a password"))
		parser.add_option("--disablereqother", action="store_true",
			help=_("do not require other characters in a password"))
		
		parser.add_option("--enablefaillock", action="store_true",
			help=_("enable account locking in case of too many consecutive authentication failures"))
		parser.add_option("--disablefaillock", action="store_true",
			help=_("disable account locking on too many consecutive authentication failures"))
		parser.add_option("--faillockargs", metavar=_("<options>"),
			help=_("the pam_faillock module options"))

		parser.add_option("--nostart", action="store_true",
			help=_("do not start/stop portmap, ypbind, and nscd"))

		parser.add_option("--test", action="store_true",
			help=_("do not update the configuration files, only print new settings"))

		parser.add_option("--update", "--kickstart", action="store_true",
			help=_("opposite of --test, update configuration files with changed settings"))

		parser.add_option("--updateall", action="store_true",
			help=_("update all configuration files"))

		parser.add_option("--probe", action="store_true",
			help=_("probe network for defaults and print them"))

		parser.add_option("--savebackup", metavar=_("<name>"),
			help=_("save a backup of all configuration files"))

		parser.add_option("--restorebackup", metavar=_("<name>"),
			help=_("restore the backup of configuration files"))

		parser.add_option("--restorelastbackup", action="store_true",
			help=_("restore the backup of configuration files saved before the previous configuration change"))

		(self.options, args) = parser.parse_args()

		if args:
			self.printError(_("unexpected argument"))
			sys.exit(2)

		if (not self.options.probe and
			not self.options.test and not self.options.update and not self.options.updateall
			and not self.options.savebackup and not self.options.restorebackup
			and not self.options.restorelastbackup):
			# --update (== --kickstart) or --test or --probe must be specified
			# this will print usage and call sys.exit()
			parser.print_help()
			sys.exit(2)

	def probe(self):
		info = authinfo.AuthInfo(self.printError)
		info.probe()
		if info.ldapServer and info.ldapBaseDN:
			print("ldap %s/%s\n" % (info.ldapServer,
				info.ldapBaseDN))
		if info.kerberosRealm:
			print("krb5 %s/%s/%s\n" % (info.kerberosRealm,
				info.kerberosKDC or "", info.kerberosAdminServer or ""))

	def readAuthInfo(self):
		self.info = authinfo.read(self.printError)
		# FIXME: what about printing critical errors reading individual configs?
		self.pristineinfo = self.info.copy()
		if self.info.enableLocAuthorize == None:
			self.info.enableLocAuthorize = True # ON by default

	def testAvailableSubsys(self):
		self.nis_avail = (os.access(authinfo.PATH_YPBIND, os.X_OK) and
			os.access(authinfo.PATH_LIBNSS_NIS, os.X_OK))
		self.kerberos_avail = os.access(authinfo.PATH_PAM_KRB5, os.X_OK)
		self.ldap_avail = (os.access(authinfo.PATH_PAM_LDAP, os.X_OK) and
			os.access(authinfo.PATH_LIBNSS_LDAP, os.X_OK))
		self.sssd_avail = (os.access(authinfo.PATH_PAM_SSS, os.X_OK) and
			os.access(authinfo.PATH_LIBNSS_SSS, os.X_OK))
		self.cache_avail = os.access(authinfo.PATH_NSCD, os.X_OK)
		self.fprintd_avail = os.access(authinfo.PATH_PAM_FPRINTD, os.X_OK)

	def overrideSettings(self):
		bool_settings = {"shadow":"enableShadow",
			"locauthorize":"enableLocAuthorize",
			"pamaccess":"enablePAMAccess",
			"sysnetauth":"enableSysNetAuth",
			"mkhomedir":"enableMkHomeDir",
			"cache":"enableCache",
			"ecryptfs":"enableEcryptfs",
			"ldap":"enableLDAP",
			"ldaptls":"enableLDAPS",
			"rfc2307bis":"enableRFC2307bis",
			"ldapauth":"enableLDAPAuth",
			"krb5":"enableKerberos",
			"nis":"enableNIS",
			"krb5kdcdns":"kerberosKDCviaDNS",
			"krb5realmdns":"kerberosRealmviaDNS",
			"smartcard":"enableSmartcard",
			"fingerprint":"enableFprintd",
			"requiresmartcard":"forceSmartcard",
			"winbind":"enableWinbind",
			"winbindauth":"enableWinbindAuth",
			"winbindusedefaultdomain":"winbindUseDefaultDomain",
			"winbindoffline":"winbindOffline",
			"winbindkrb5":"winbindKrb5",
			"sssd":"enableSSSD",
			"sssdauth":"enableSSSDAuth",
			"forcelegacy":"enableForceLegacy",
			"cachecreds":"enableCacheCreds",
			"preferdns":"preferDNSinHosts",
                        "reqlower":"passReqLower",
                        "requpper":"passReqUpper",
                        "reqdigit":"passReqDigit",
                        "reqother":"passReqOther",
                        "faillock":"enableFaillock"}

		string_settings = {"passalgo":"passwordAlgorithm",
			"ldapserver":"ldapServer",
			"ldapbasedn":"ldapBaseDN",
			"ldaploadcacert":"ldapCacertURL",
			"krb5realm":"kerberosRealm",
			"krb5kdc":"kerberosKDC",
			"krb5adminserver":"kerberosAdminServer",
			"smartcardmodule":"smartcardModule",
			"smartcardaction":"smartcardAction",
			"nisdomain":"nisDomain",
			"nisserver":"nisServer",
			"smbworkgroup":"smbWorkgroup",
			"smbservers":"smbServers",
			"smbsecurity":"smbSecurity",
			"smbrealm" : "smbRealm",
			"smbidmaprange":"smbIdmapRange",
			"winbindseparator":"winbindSeparator",
			"winbindtemplatehomedir":"winbindTemplateHomedir",
			"winbindtemplateshell":"winbindTemplateShell",
                        "passminlen":"passMinLen",
                        "passminclass":"passMinClass",
                        "passmaxrepeat":"passMaxRepeat",
                        "passmaxclassrepeat":"passMaxClassRepeat",
                        "faillockargs":"faillockArgs"}

		for opt, aival in bool_settings.items():
			if getattr(self.options, "enable"+opt):
				setattr(self.info, aival, True)
			if getattr(self.options, "disable"+opt):
				setattr(self.info, aival, False)

		try:
			if self.info.enableRFC2307bis:
				self.info.ldapSchema = 'rfc2307bis'
			else:
				self.info.ldapSchema = ''
		except AttributeError:
			pass

		if self.options.krb5realm and self.options.krb5realm != self.info.kerberosRealm:
			self.info.kerberosKDC = self.info.getKerberosKDC(self.options.krb5realm)
			self.info.kerberosAdminServer = self.info.getKerberosAdminServer(self.options.krb5realm)

		try:
            		val = self.options.passminlen
            		if val != None:
            			val = int(val)
            			if val < 6:
            				self.printError(_("The passminlen minimum value is 6"))
            				self.options.passminlen = None
            				self.retval = 3
		except ValueError:
			self.printError(_("The passminlen option value is not an integer"))
			self.options.passminlen = None
			self.retval = 3
		try:
            		val = self.options.passminclass
            		if val != None:
            			val = int(val)
            			if val < 0:
            				self.printError(_("The passminclass value must not be negative"))
            				self.options.passminclass = None
            				self.retval = 3
            			if val > 4:
            				self.printError(_("The passminclass value must not be higher than 4"))
            				self.options.passminclass = None
            				self.retval = 3
		except ValueError:
			self.printError(_("The passminclass option value is not an integer"))
			self.options.passminclass = None
			self.retval = 3
		try:
            		val = self.options.passmaxrepeat
            		if val != None:
            			val = int(val)
            			if val < 0:
            				self.printError(_("The passmaxrepeat value must not be negative"))
            				self.options.passmaxrepeat = None
            				self.retval = 3
		except ValueError:
			self.printError(_("The passmaxrepeat option value is not an integer"))
			self.options.passmaxrepeat = None
			self.retval = 3
		try:
            		val = self.options.passmaxclassrepeat
            		if val != None:
            			val = int(val)
            			if val < 0:
            				self.printError(_("The passmaxclassrepeat value must not be negative"))
            				self.options.passmaxclassrepeat = None
            				self.retval = 3
		except ValueError:
			self.printError(_("The passmaxclassrepeat option value is not an integer"))
			self.options.passmaxclassrepeat = None
			self.retval = 3

		for opt, aival in string_settings.items():
			if getattr(self.options, opt) != None:
				setattr(self.info, aival, getattr(self.options, opt))

		if self.options.winbindjoin:
			lst = self.options.winbindjoin.split("%", 1)
			self.info.joinUser = lst[0]
			if len(lst) > 1:
				self.info.joinPassword = lst[1]

		if self.options.smartcardaction:
			try:
				idx = int(self.options.smartcardaction)
				self.info.smartcardAction = authinfo.getSmartcardActions()[idx]
			except (ValueError, IndexError):
				self.printError(_("Bad smart card removal action specified."))
				self.info.smartcardAction = ""

		if self.options.enablerequiresmartcard and self.options.smartcardmodule == "sssd":
			self.printError(_("--enablerequiresmartcard is not supported for module 'sssd', option is ignored."))
			self.options.enablerequiresmartcard = False

		if not self.options.passalgo:
			if self.options.enablemd5:
				self.info.passwordAlgorithm = "md5"
			if self.options.disablemd5:
				self.info.passwordAlgorithm = "descrypt"
		elif self.options.passalgo not in authinfo.password_algorithms:
			self.printError(_("Unknown password hashing algorithm specified, using sha256."))
			self.info.passwordAlgorithm = "sha256"
			self.retval = 3

	def doUI(self):
		return True

	def joinDomain(self):
		ret = True
		if self.options.winbindjoin:
			ret = self.info.joinDomain(True)
		return ret

	def writeAuthInfo(self):
		self.info.testLDAPCACerts()
		if self.info.ldapCacertURL:
			if not self.info.downloadLDAPCACert():
				self.retval = 4
		self.info.rehashLDAPCACerts()
		if self.options.updateall:
			if not self.info.write():
				self.retval = 5
		else:
			if not self.info.writeChanged(self.pristineinfo):
				self.retval = 6
		# FIXME: what about printing critical errors writing individual configs?
		if not self.joinDomain():
			self.retval = 7
		self.info.post(self.options.nostart)

	def run(self):
		self.parseOptions()
		if self.options.probe:
			self.probe()
			sys.exit(0)
		if not self.options.test and os.getuid() != 0:
			self.printError(_("can only be run as root"))
			sys.exit(2)
		self.readAuthInfo()
		if self.options.restorelastbackup:
			rv = self.info.restoreLast()
			sys.exit(int(not rv))
		if self.options.restorebackup:
			rv = self.info.restoreBackup(self.options.restorebackup)
			sys.exit(int(not rv))
		if self.options.savebackup:
			rv = self.info.saveBackup(self.options.savebackup)
			sys.exit(int(not rv))
		self.testAvailableSubsys()
		self.overrideSettings()
		if not self.doUI():
			if self.options.test:
				self.printError(_("dialog was cancelled"))
			sys.exit(1)
		if self.options.test:
			self.info.printInfo()
		else:
			self.writeAuthInfo()
		return self.retval

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	gettext.textdomain("authconfig")
	module = Authconfig()
	sys.exit(module.run())
