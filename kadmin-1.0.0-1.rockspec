 package = "kadmin"
 version = "1.0.0-1"
 source = {
    url = "git://github.com/JorjBauer/lua-kadmin",
    tag = "v1.0.0"
 }
 description = {
    summary = "Kadmin library for Lua 5.1+",
    detailed = [[Bindings for the MIT kadmin interface
    ]],
    homepage = "http://github.com/JorjBauer/lua-kadmin",
    license = "BSD"
 }
 dependencies = {
    "lua >= 5.1",
 }
 external_dependencies = {
    LIBKRB = {
       header = "krb5.h"
    }
 }
 build = {
    type = "builtin",
    modules = { 
    	    kadmin = { 
	    	   sources = { "kadmin.c", "context.c" },
		   libraries = { "krb" },
		   defines = { 'VERSION="1.1"' },
	    }
    },
 }
