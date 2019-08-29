#include <lua.h>
#include <lauxlib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "context.h"

/* metatable, hook for calling gc_context on context structs */
static const luaL_Reg meta[] = {
  /*  { "__gc", gc_context },*/
  { NULL,   NULL        }
};

/* function table for this module */
static const struct luaL_Reg methods[] = {
  // Methods to set the configuration
  { "setRealm",              setRealmFunc                       },
  { "setAdminServer",        setAdminServerFunc                 },

  
  // Methods to interact with Kerberos
  { "initWithSkey",          initWithSkeyFunc                   },
  { "initWithPassword",      initWithPasswordFunc               },
  { "getPrincipal",          getPrincipalFunc                   },
  { "getPrincipals",         getPrincipalsFunc                  },
  { "createPrincipal",       createPrincipalFunc                },
  { "deletePrincipal",       deletePrincipalFunc                },
  { "lockPrincipal",         lockPrincipalFunc                  },
  { "unlockPrincipal",       unlockPrincipalFunc                },
  { "setPasswordExpiration", setPasswordExpirationFunc          },
  { "changePassword",        changePasswordFunc                 },

  // Methods to retrieve state data
  { "error",                 errorFunc                          },

  // ... and we're done.
  { NULL,                    NULL                               }
};

/* Module initializer, called from Lua when the module is loaded. */
int luaopen_kadmin(lua_State *L)
{
  /* Create metatable, which is used to tie C data structures to our garbage 
   * collection function. */
  luaL_newmetatable(L, MODULENAME);
#if LUA_VERSION_NUM == 501
  luaL_openlib(L, 0, meta, 0);
#else
  lua_newtable(L);
  luaL_setfuncs(L, meta, 0);
#endif
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);                  /* hide metatable:
                                         metatable.__metatable = methods */
  lua_pop(L, 1);                      /* drop metatable */

  /* Construct a new namespace table for Luaand return it. */
#if LUA_VERSION_NUM == 501
  /* Lua 5.1: pollute the root namespace */
  luaL_openlib(L, MODULENAME, methods, 0);
#else
  /* Lua 5.2 and above: be a nice namespace citizen */
  lua_newtable(L);
  luaL_setfuncs(L, methods, 0);
#endif

  kadm_init();

  return 1;                           /* return methods table on the stack */

}

