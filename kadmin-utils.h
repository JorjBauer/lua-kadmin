#ifndef __KADMIN_UTILS_H
#define __KADMIN_UTILS_H

/* Kerberos methods on MacOS are marked as deprecated, but that's
   specifically to mark the GSSAPI deprecated. There's no replacement
   way to perform the direct Kerberos library work, so we'll suppress
   warnings here. */
#define KERBEROS_APPLE_DEPRECATED(x)

#include <krb5/krb5.h>
#include <kadm5/admin.h>
#include <kadm5/kadm_err.h>

char *kadm_obtain_errormsg(void);

kadm5_ret_t kadm_init();

kadm5_ret_t kadm_setRealm (const char *realm);
kadm5_ret_t kadm_setAdminServer(const char *s);

kadm5_ret_t kadm_initWithSkey(const char *princ, const char *keytabPath, const char *serviceName);
kadm5_ret_t kadm_initWithPassword(const char *princ, const char *password, const char *serviceName);

kadm5_ret_t kadm_getPrinc(const char *princ, kadm5_principal_ent_rec *toWhere);
kadm5_ret_t kadm_getPrincs(const char *expr, char ***princList, int *count);

kadm5_ret_t kadm_createPrincipal(const char *princ, const char *pw);
kadm5_ret_t kadm_deletePrincipal(const char *princ);
kadm5_ret_t kadm_modifyPrincipal(kadm5_principal_ent_rec *princ, long mask);

kadm5_ret_t kadm_changePassword(const char *princ, const char *pw);

kadm5_ret_t kadm_freePrincipalEnt(kadm5_principal_ent_rec *what);
kadm5_ret_t kadm_freeNameList(char **nameList, int count);

int testKadmin();


#endif
