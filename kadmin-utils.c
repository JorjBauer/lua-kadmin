#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "kadmin-utils.h"

krb5_ccache          _cc;
kadm5_config_params  _params;
krb5_context         _context;
int                  _contextInitialized = 0;
void                *_serverHandle = NULL;


static char kadm_error_message[256] = { '\0' };

#define FAIL(err, tag) \
  if (err) { \
  (void) snprintf(kadm_error_message, 256, "%s %s", \
		  error_message(err), tag);         \
                  goto cleanup;			    \
  }

char *kadm_obtain_errormsg(void) {
  return kadm_error_message;
}

kadm5_ret_t kadm_init()
{
  kadm5_ret_t ret = 0;

  if (_contextInitialized) {
    krb5_free_context(_context);
    _contextInitialized = 0;
  }
  
  ret = krb5_init_context(&_context);
  FAIL(ret, "from kadm5_init_krb5_context");

  _contextInitialized = 1;
  
  memset(&_params, 0, sizeof(_params));

  ret = krb5_cc_default(_context, &_cc);
  FAIL(ret, "from krb5_cc_default");

 cleanup:
  return ret;
}


kadm5_ret_t kadm_initWithSkey(const char *princ, const char *keytabPath, const char *serviceName)
{
  kadm5_ret_t ret = 0;
  char **dbargs = NULL;

  if (_serverHandle) {
    kadm5_destroy(_serverHandle);
    _serverHandle = NULL;
  }
  
  ret = kadm5_init_with_skey(_context,
			     (char *)princ,
			     (char *)keytabPath,
			     (char *)serviceName,
			     &_params,
			     KADM5_STRUCT_VERSION,
			     KADM5_API_VERSION_2,
			     dbargs,
			     &_serverHandle);
  FAIL(ret, "from kadm5_init_with_skey");

 cleanup:
  return ret;
}

kadm5_ret_t kadm_initWithPassword(const char *princ, const char *pw, const char *serviceName)
{
  kadm5_ret_t ret = 0;
  char **dbargs = NULL;

  if (_serverHandle) {
    kadm5_destroy(_serverHandle);
    _serverHandle = NULL;
  }
  
  ret = kadm5_init_with_password(_context,
				 (char *)princ,
				 (char *)pw,
				 (char *)serviceName,
				 &_params,
				 KADM5_STRUCT_VERSION,
				 KADM5_API_VERSION_2,
				 dbargs,
				 &_serverHandle);
  FAIL(ret, "from kadm5_init_with_password");
  
 cleanup:
  return ret;
}

int kadm_testKadmin()
{
  void *serverHandle = NULL;
  
  krb5_error_code err = 0;
  kadm5_ret_t ret = 0;

  kadm5_config_params params;
  memset(&params, 0, sizeof(params));
  params.mask |= KADM5_CONFIG_REALM | KADM5_CONFIG_ADMIN_SERVER;
  char realmName[255];
  snprintf(realmName, sizeof(realmName), "NPKDC.TEMPLE.EDU");
  params.realm = realmName;
  char adminServer[255];
  snprintf(adminServer, sizeof(adminServer), "np-krb1.temple.edu:749");
  params.admin_server = adminServer;

  krb5_ccache cc;
  ret = krb5_cc_default(_context, &cc);
  FAIL(ret, "from krb5_cc_default");

  char *princName = "AccessNet/createkey@NPKDC.TEMPLE.EDU";
  char *keytabPath = "./np-createkey.keytab";
  //char *serviceName = "AccessNet/createkey";
  char **dbargs = NULL;

  // FIXME: serviceName optional (and NULL below, so)
  
  ret = kadm5_init_with_skey(_context,
			     princName,
			     keytabPath,
			     NULL,
			     &params,
			     KADM5_STRUCT_VERSION,
			     KADM5_API_VERSION_2,
			     dbargs,
			     &serverHandle);
  FAIL(ret, "from kadm5_init_with_skey");

  // Perform work here
  kadm5_principal_ent_rec principal_to_find;
  memset((void *)&principal_to_find, 0, sizeof(principal_to_find));
  krb5_parse_name(_context, "tug35038@NPKDC.TEMPLE.EDU", &(principal_to_find.principal));
  
  kadm5_principal_ent_rec principalData;
  ret = kadm5_get_principal( serverHandle,
			     principal_to_find.principal,
			     &principalData,
			     KADM5_PRINCIPAL_NORMAL_MASK );
  FAIL(ret, "from kadm5_get_principal");

  /*
  printf("pw expiration: %d\n", principalData.pw_expiration);
  printf("princ expiration: %d\n", principalData.princ_expire_time);
  printf("last pw change: %d\n", principalData.last_pwd_change);
  printf("last success: %d\n", principalData.last_success);
  printf("last failed: %d\n", principalData.last_failed);
  printf("kvno: %d\n", principalData.kvno);
  printf("policy: %s\n", principalData.policy);
  printf("last modified: %d\n", principalData.mod_date);
  */
  //  printf("last mod by: %s\n", principalData.mod_name.principal);

  /* lock:
krb5_timestamp now;
krb5_timeofday(context, &now);
principal.princ_expire_time = now;

... OR
char *timestamp = 'tomorrow 1 pm';
krb5_timestamp when;
krb5_string_to_timestamp(timestamp, &when);
principal.princ_expire_time = when;
  */

  kadm5_free_principal_ent(serverHandle, &principalData);
  krb5_free_principal(_context, principal_to_find.principal);
  
  ret = krb5_cc_close(_context, cc);
  FAIL(ret, "from krb5_cc_close");

 cleanup:
  return err || ret;
}

kadm5_ret_t kadm_setRealm(const char *realm)
{
  assert(realm && strlen(realm));

  // FIXME: what if it was already set
  _params.mask |= KADM5_CONFIG_REALM;
  _params.realm = malloc(strlen(realm)+1);
  assert(_params.realm);
  strcpy(_params.realm, realm);

  return 0; // success
}

kadm5_ret_t kadm_setAdminServer(const char *s)
{
  assert(s && strlen(s));

  _params.mask |= KADM5_CONFIG_ADMIN_SERVER;
  _params.admin_server = malloc(strlen(s)+1);
  assert(_params.admin_server);
  strcpy(_params.admin_server, s);

  return 0; // success
}

// princ like 'tug35038@NPKDC.TEMPLE.EDU'
// if successful, caller must call kadm_freePrincipalEnt(toWhere) to clean up
kadm5_ret_t kadm_getPrinc(const char *princ, kadm5_principal_ent_rec *toWhere)
{
  kadm5_ret_t ret = 0;

  assert(princ && strlen(princ));
  assert(toWhere);

  kadm5_principal_ent_rec principal_to_find;
  memset((void *)&principal_to_find, 0, sizeof(principal_to_find));
  ret = krb5_parse_name(_context, princ, &(principal_to_find.principal));
  FAIL(ret, "from krb5_parse_name");

  ret = kadm5_get_principal( _serverHandle,
			     principal_to_find.principal,
			     toWhere,
			     KADM5_PRINCIPAL_NORMAL_MASK );
  FAIL(ret, "from kadm5_get_principal");

  // FIXME: return undef if it's not found
  // napi_value undefined;
  // status = napi_get_undefined(env, &undefined);

  krb5_free_principal(_context, principal_to_find.principal);
  
 cleanup:
  return ret;
}

// on success, kadm5_free_name_list() must be called by the caller on the returned princList
kadm5_ret_t kadm_getPrincs(const char *expr, char ***princList, int *count)
{
  kadm5_ret_t ret = 0;
  *count = 0;
  
  ret = kadm5_get_principals( _serverHandle,
			      (char *)expr,
			      princList,
			      count );
  FAIL(ret, "from kadm5_get_principals");
  
 cleanup:
  return ret;
}

// FIXME: missing, add these:  policyname & (arbitrary) flags
kadm5_ret_t kadm_createPrincipal(const char *princ, const char *pw)
{
  kadm5_ret_t ret = 0;

  assert(princ);
  assert(pw);

  long mask = 0;
  kadm5_principal_ent_rec principal;
  memset((void *)&principal, 0, sizeof(principal));
  ret = krb5_parse_name(_context, princ, &(principal.principal));
  mask |= KADM5_PRINCIPAL;

  // To update the principal further, we'd do something like ...
  // principal.attributes = KADM5_LAST_SUCCESS | KADM5_PRINC_EXPIRE_TIME; mask |= KADM5_ATTRIBUTES;
  // principal.policy = strdup("something"); mask |= KADM5_POLICY;
  
  ret = kadm5_create_principal( _serverHandle,
				&principal,
				mask & (~KADM5_POLICY_CLR | KADM5_FAIL_AUTH_COUNT),
				(char *)pw );
  FAIL(ret, "from kadm5_create_principal");
  
 cleanup:
  return ret;
}

kadm5_ret_t kadm_deletePrincipal(const char *princ)
{
  kadm5_ret_t ret = 0;

  assert(princ);

  kadm5_principal_ent_rec principal;
  memset((void *)&principal, 0, sizeof(principal));
  ret = krb5_parse_name(_context, princ, &(principal.principal));

  ret = kadm5_delete_principal( _serverHandle,
				principal.principal );
  FAIL(ret, "from kadm5_delete_principal");
  
 cleanup:
  return ret;
}

kadm5_ret_t kadm_modifyPrincipal(kadm5_principal_ent_rec *princ, long mask)
{
  kadm5_ret_t ret = 0;

  assert(princ);

  ret = kadm5_modify_principal( _serverHandle,
				princ,
				mask );
  FAIL(ret, "from kadm5_delete_principal");
  
 cleanup:
  return ret;
}


kadm5_ret_t kadm_changePassword(const char *princ, const char *pw)
{
  kadm5_ret_t ret = 0;
  
  assert(princ);
  
  kadm5_principal_ent_rec principal;
  memset((void *)&principal, 0, sizeof(principal));
  ret = krb5_parse_name(_context, princ, &(principal.principal));
  
  ret = kadm5_chpass_principal( _serverHandle,
				principal.principal,
				(char *)pw );
  FAIL(ret, "from kadm5_chpass_principal");

 cleanup:
  return ret;
}

  

kadm5_ret_t kadm_freePrincipalEnt(kadm5_principal_ent_rec *what)
{
  return kadm5_free_principal_ent(_serverHandle, what);
}

kadm5_ret_t kadm_freeNameList(char **nameList, int count)
{
  return kadm5_free_name_list(_serverHandle, nameList, count);
}

