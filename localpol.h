/* In order to present the option to use a local policy in the system-auth
   configuration file, you must build with
   make EXTRA_CFLAGS=-DLOCAL_POLICIES
   and change these strings if you want... */
#ifndef LOCAL_POLICY_NAME
#define LOCAL_POLICY_NAME "local-policy"
#endif
#ifndef LOCAL_POLICY_COMMENT
#define LOCAL_POLICY_COMMENT i18n("Use Local Policies")
#endif
