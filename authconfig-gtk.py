#!/usr/bin/python2.2
import gtk, gtk.glade, authconfig;

main_map = {
	"enablecache" : ("enableCache", "/usr/sbin/nscd", "caching", "nscd"),
	"enablenis" : ("enableNIS", "/usr/sbin/ypbind", "NIS", "ypbind"),
	"enableldap" : ("enableLDAP", "/lib/libnss_ldap.so.2", "LDAP", "nss_ldap"),
	"enableldapauth" : ("enableLDAPAuth", "/lib/security/pam_ldap.so", "LDAP", "nss_ldap"),
	"enablekerberos" : ("enableKerberos", "/lib/security/pam_krb5.so", "Kerberos", "pam_krb5"),
	"enablesmb" : ("enableSMB", "/lib/security/pam_smb_auth.so", "SMB", "pam_smb"),
}

if __name__ == '__main__':
	xml = gtk.glade.XML("authconfig.glade2","authconfig","authconfig")
	win = xml.get_widget("authconfig")
	win.show()
	#gtk.main()
