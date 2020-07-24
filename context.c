#include <lua.h>
#include <lauxlib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "context.h"

/* strdup() is a POSIX function that is not part of the ANSI standard. This
 * simple wrapper provides the same functionality for platforms that don't
 * have POSIX defined. */
char *local_strdup(const char *s1)
{
#ifdef POSIX
  return strdup(s1);
#else
  char *ret = malloc(strlen(s1)+1);
  if (!ret)
    return NULL;

  strcpy(ret, s1);

  return ret;
#endif
}
#define ERROR(x) { lua_pushstring(l, x); lua_error(l); }
#define getn(L,n) (luaL_checktype(L, n, LUA_TTABLE), luaL_getn(L, n))

int setRealmFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.setRealm(<realm>)");
  }

  const char *realm = lua_tostring(l, 1);

  lua_pushinteger(l, kadm_setRealm(realm));
  return 1; // number of arguments on the stack
}

int setAdminServerFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.setAdminServer(<adminServer:port>)");
  }

  const char *svr = lua_tostring(l, 1);

  lua_pushinteger(l, kadm_setAdminServer(svr));
  return 1; // number of arguments on the stack
}

int initWithSkeyFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs < 2 || numargs > 3) {
    ERROR("usage: kadmin.initWithSkey(<principal>, <keytab> [, servicename])");
  }

  const char *princ = lua_tostring(l, 1);
  const char *keytab = lua_tostring(l, 2);
  const char *servicename = NULL;
  if (numargs == 3) {
    servicename = lua_tostring(l, 3);
  }

  printf("princ: %s; keytab: %s; servicename: %s\n", princ, keytab, servicename ? servicename : "<NULL>");
  int err = kadm_initWithSkey(princ, keytab, servicename);

  lua_pushinteger(l, err);
  return 1; // number of arguments on the stack
}

int initWithPasswordFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs < 2 || numargs > 3) {
    ERROR("usage: kadmin.initWithPassword(<principal>, <password> [, servicename])");
  }

  const char *princ = lua_tostring(l, 1);
  const char *password = lua_tostring(l, 2);
  const char *servicename = NULL;
  if (numargs == 3) {
    servicename = lua_tostring(l, 3);
  }
  
  int err = kadm_initWithPassword(princ, password, servicename);

  lua_pushinteger(l, err);
  return 1; // number of arguments on the stack
}

int getPrincipalFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.getPrincipal(<principal>)");
  }

  const char *princ = lua_tostring(l, 1);
  kadm5_principal_ent_rec result;
  kadm5_ret_t err = kadm_getPrinc(princ, &result);
  if (err) {
    // FIXME: probably not the best, just returning nil - should raise some errors?
    lua_pushnil(l);
    return 1;
  }

  _packOnePrincOnStack(l, &result);

  kadm_freePrincipalEnt(&result);

  return 1; // number of arguments on the stack
}

int getPrincipalsFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs > 1) {
    ERROR("usage: kadmin.getPrincipals([pattern])");
  }

  const char *p = NULL; // optional search pattern
  if (numargs == 1) {
    p = lua_tostring(l, 1);
  }

  char **princList = NULL;
  int count = 0;
  kadm5_ret_t ret = kadm_getPrincs(p, &princList, &count);
  if (ret) {
    // FIXME: probably not the best, just returning nil - should raise some errors?
    lua_pushnil(l);
    return 1;
  }

  lua_newtable(l); // Construct the resulting array on the stack

  // Push each element on the stack, then push that element in to the table
  for (int i=0; i<count; i++) {
    lua_pushstring(l, princList[i]);
    lua_rawseti(l, -2, i+1);
  }

  kadm_freeNameList(princList, count);

  return 1; // number of arguments on the stack (just the array)
}

int createPrincipalFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 2) {
    ERROR("usage: kadmin.createPrincipal(<princ>, <password>)");
  }

  const char *princ = lua_tostring(l, 1);
  const char *pw = lua_tostring(l, 2);
  
  lua_pushinteger(l, kadm_createPrincipal(princ, pw));

  return 1;
}

int deletePrincipalFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.deletePrincipal(<princ>)");
  }

  const char *princ = lua_tostring(l, 1);
  
  lua_pushinteger(l, kadm_deletePrincipal(princ));

  return 1;
}

int lockPrincipalFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.lockPrincipal(<princ>)");
  }

  const char *princName = lua_tostring(l, 1);

  kadm5_principal_ent_rec princ;
  kadm5_ret_t ret = kadm_getPrinc(princName,
                                  &princ);
  if (ret) {
    lua_pushinteger(l, ret);
    return 1;
  }

  unsigned long now = time(NULL);
  princ.princ_expire_time = now;
  ret = kadm_modifyPrincipal(&princ, KADM5_PRINC_EXPIRE_TIME);

  lua_pushinteger(l, ret);
  return 1;
}

int unlockPrincipalFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    ERROR("usage: kadmin.unlockPrincipal(<princ>)");
  }

  const char *princName = lua_tostring(l, 1);
  unsigned long etime = lua_tointeger(l, 2);

  kadm5_principal_ent_rec princ;
  kadm5_ret_t ret = kadm_getPrinc(princName,
                                  &princ);
  if (ret) {
    lua_pushinteger(l, ret);
    return 1;
  }

  princ.princ_expire_time = 0;
  princ.fail_auth_count = 0;
  ret = kadm_modifyPrincipal(&princ, KADM5_PRINC_EXPIRE_TIME | KADM5_FAIL_AUTH_COUNT);

  lua_pushinteger(l, ret);
  return 1;
}

int setPasswordExpirationFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 2) {
    ERROR("usage: kadmin.setPasswordExpiration(<princ>, <epochtime>)");
  }

  const char *princName = lua_tostring(l, 1);

  kadm5_principal_ent_rec princ;
  kadm5_ret_t ret = kadm_getPrinc(princName,
                                  &princ);
  if (ret) {
    lua_pushinteger(l, ret);
    return 1;
  }

  princ.pw_expiration = lua_tointeger(l, 2);
  ret = kadm_modifyPrincipal(&princ, KADM5_PW_EXPIRATION);

  lua_pushinteger(l, ret);
  return 1;
}

int changePasswordFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 2) {
    ERROR("usage: kadmin.changePassword(<princ>, <pw>)");
  }

  const char *princName = lua_tostring(l, 1);
  const char *pw = lua_tostring(l, 2);

  lua_pushinteger(l, kadm_changePassword(princName, pw));
  return 1;
}

int errorFunc(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs > 0) {
    ERROR("usage: kadmin.error()");
  }

  lua_pushstring(l, kadm_obtain_errormsg());
  return 1;
}


void _packOnePrincOnStack(lua_State *l, kadm5_principal_ent_rec *per)
{
  lua_createtable(l, 0, 8);

  lua_pushstring(l, "pw_expiration");
  lua_pushinteger(l, per->pw_expiration);
  lua_settable(l, -3);

  lua_pushstring(l, "princ_expire_time");
  lua_pushinteger(l, per->princ_expire_time);
  lua_settable(l, -3);

  lua_pushstring(l, "last_pwd_change");
  lua_pushinteger(l, per->last_pwd_change);
  lua_settable(l, -3);

  lua_pushstring(l, "last_success");
  lua_pushinteger(l, per->last_success);
  lua_settable(l, -3);

  lua_pushstring(l, "last_failed");
  lua_pushinteger(l, per->last_failed);
  lua_settable(l, -3);

  lua_pushstring(l, "kvno");
  lua_pushinteger(l, per->kvno);
  lua_settable(l, -3);

  lua_pushstring(l, "policy");
  lua_pushstring(l, per->policy);
  lua_settable(l, -3);

  lua_pushstring(l, "mod_date");
  lua_pushinteger(l, per->mod_date);
  lua_settable(l, -3);

  lua_pushstring(l, "attributes");
  lua_pushinteger(l, per->attributes);
  lua_settable(l, -3);
}
