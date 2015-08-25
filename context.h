#ifndef __CONTEXT_H
#define __CONTEXT_H

#include <lua.h>
#include <lauxlib.h>

#include <krb5.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LKRB5_MAGIC 0x4c4b5242
#define MODULENAME      "kadmin"

struct _krb_ctx {
  unsigned long   magic;
};

struct _krb_ctx **new_context(lua_State *L);
struct _krb_ctx  *get_context(lua_State *l, int idx);

int  gc_context  (lua_State *L);
void free_context(struct _krb_ctx *ctx);

#endif
