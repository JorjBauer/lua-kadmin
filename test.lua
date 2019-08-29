#!/usr/bin/env lua

local kadmin = require "kadmin"
local os = require "os"
local inspect = require "inspect"

kadmin.setRealm('NPKDC.TEMPLE.EDU')
kadmin.setAdminServer('np-krb1.temple.edu:749')


local err = kadmin.initWithSkey("AccessNet/createkey@NPKDC.TEMPLE.EDU", "./np-createkey.keytab")
if (err ~= 0) then
   print("error: " .. kadmin.error())
   os.exit(1)
end

-- get all the principals
local allUsers = kadmin.getPrincipals()
print(inspect(allUsers))

-- just the admin princs
local allAdminPrincs = kadmin.getPrincipals("*/admin")
print(inspect(allAdminPrincs))

-- get the details of one princ
local oneUser = kadmin.getPrincipal('tuh19725')
if (oneUser == nil) then
   print("error: " .. kadmin.error())
   os.exit(1)
else
   print(inspect(oneUser))
end

-- create a principal
local ret = kadmin.createPrincipal('tug35038/test', 'thisisagreattestpassword')
if (ret ~= 0) then
   local err = kadmin.error()
   print("Error while creating principal: " .. err)
   os.exit(1)
else
   print("Successfully created user")
end

-- test changing a password
ret = kadmin.changePassword('tug35038/test', 'thisisagreatnewtestpassword')
if (ret ~= 0) then
   local err = kadmin.error()
   print("Error while changing password: " .. err)
   os.exit(1)
else
   print("Successfully changed password")
end

-- test changing the password as the user
ret = kadmin.initWithPassword('tug35038/test', 'thisisagreatnewtestpassword')
if (ret ~= 0) then
   local err = kadmin.error()
   print("Error while initing as user: " .. err)
--   os.exit(1)
else
   print("Successfully logged back in as the user") 
end

ret = kadmin.changePassword('tug35038/test', 'thisisanothernewgreattestpassword')
if (ret ~= 0) then
   local err = kadmin.error()
   print("Error while changing password as user: " .. err)
else
   print("Successfully changed password as user")
end

-- back to admin to delete the principal
local err = kadmin.initWithSkey("AccessNet/createkey@NPKDC.TEMPLE.EDU", "./np-createkey.keytab")
if (err ~= 0) then
   print("error: " .. kadmin.error())
   os.exit(1)
else
   print("Successfully re-authed with keytab")
end

ret = kadmin.lockPrincipal('tug35038/test')
if (ret ~= 0) then
   print("Error: " .. kadmin.error())
   os.exit(1)
else
   print("successfully locked")
end

-- print it
oneUser = kadmin.getPrincipal('tug35038/test')
if (oneUser == nil) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print(inspect(oneUser))
end

ret = kadmin.unlockPrincipal('tug35038/test')
if (ret ~= 0) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print("successfully unlocked")
end

-- print it
oneUser = kadmin.getPrincipal('tug35038/test')
if (oneUser == nil) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print(inspect(oneUser))
end

local now = os.time()
ret = kadmin.setPasswordExpiration('tug35038/test', now)
if (ret ~= 0) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print("successfully set pw expiration")
end

-- print it
oneUser = kadmin.getPrincipal('tug35038/test')
if (oneUser == nil) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print(inspect(oneUser))
end

ret = kadmin.deletePrincipal('tug35038/test')
if (ret ~= 0) then
   err = print("error: " .. kadmin.error())
   os.exit(1)
else
   print("Successfully deleted user")
end
