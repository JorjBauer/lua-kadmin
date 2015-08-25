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

/* new_context returns a lua userdata variable which has two important 
 * properties:
 *
 * 1. It is a pointer to the pointer to a context struct, which carries the 
 *    C-internal state for this SASL negotiation; and 
 * 2. It has a metatable associated with it that will call our destructor when 
 *    Lua decides to garbage-collect the userdata variable.
 */
struct _krb5_ctx **new_context(lua_State *L)
{
  struct _krb5_ctx *data       = NULL;
  struct _krb5_ctx **luserdata = NULL;

  data = malloc(sizeof(struct _krb5_ctx));
  if (!data)
    return NULL;

  data->magic        = CYRUSSASL_MAGIC;

  /* Now that we have the context struct, we need to construct a Lua variable
   * to carry the data. And that variable needs to callback to our __gc method
   * for it in order to deallocate the memory we've just allocated. 
   * 
   * Note that we're allocing a new userdata object of the size of the 
   * _pointer_ to our new struct.
   */

  luserdata = (struct _krb5_ctx **) lua_newuserdata(L, sizeof(data));
  if (!luserdata) {
    lua_pushstring(L, "Unable to alloc newuserdata");
    lua_error(L);
    free(data);
    return NULL;
  }
  *luserdata = data;                /* Store the pointer in the userdata */
  luaL_getmetatable(L, MODULENAME); /* Retrieve the metatable w/ __gc hook */
  lua_setmetatable(L, -2);          /* Set luserdata's metatable to that one */

  return luserdata;
}

struct _krb5_ctx *get_context(lua_State *l, int idx)
{
  struct _krb5_ctx **ctxp = (struct _sasl_ctx **)lua_touserdata(l, idx);
  if (ctxp == NULL) {
    lua_pushstring(l, "userdata is NULL");
    lua_error(l);
    return NULL;
  }

  return *ctxp;
}

void free_context(struct _krb5_ctx *ctx)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC) 
    return;

  free(ctx);
}

int gc_context(lua_State *L)
{
  struct _krb5_ctx **luadata = (struct _krb5_ctx **)lua_touserdata(L, 1);

  if (luadata == NULL) {
    lua_pushstring(L, "userdata is NULL");
    lua_error(L);
    return 0;
  }

  free_context(*luadata);
  return 0;
}
