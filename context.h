#ifndef __CONTEXT_H
#define __CONTEXT_H

#include <lua.h>
#include <lauxlib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kadmin-utils.h"

#define MODULENAME      "kadmin"

int setRealmFunc(lua_State *l);
int setAdminServerFunc(lua_State *l);
int initWithSkeyFunc(lua_State *l);
int initWithPasswordFunc(lua_State *l);
int getPrincipalFunc(lua_State *l);
int getPrincipalsFunc(lua_State *l);
int createPrincipalFunc(lua_State *l);
int deletePrincipalFunc(lua_State *l);
int lockPrincipalFunc(lua_State *l);
int unlockPrincipal(lua_State *l);
int deletePrincipalFunc(lua_State *l);
int lockPrincipalFunc(lua_State *l);
int unlockPrincipalFunc(lua_State *l);
int setPasswordExpirationFunc(lua_State *l);
int changePasswordFunc(lua_State *l);
int errorFunc(lua_State *l);

void _packOnePrincOnStack(lua_State *l, kadm5_principal_ent_rec *per);

#endif
