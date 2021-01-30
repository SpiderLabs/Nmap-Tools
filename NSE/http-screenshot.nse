-- Copyright (C) 2012 Trustwave
-- http://www.trustwave.com
-- 
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; version 2 dated June, 1991 or at your option
-- any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
-- 
-- A copy of the GNU General Public License is available in the source tree;
-- if not, write to the Free Software Foundation, Inc.,
-- 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

description = [[
Gets a screenshot from the host
]]

author = "Ryan Linn <rlinn at trustwave.com>"

license = "GPLv2"

categories = {"discovery", "safe"}

-- Updated the NSE Script imports and variable declarations
local shortport = require "shortport"

local stdnse = require "stdnse"

-- Added HTTP to detect response code to abort on 401
local http = require "http"

portrule = shortport.http

action = function(host, port)
	-- Check to see if ssl is enabled, if it is, this will be set to "ssl"
	local ssl = port.version.service_tunnel

	-- The default URLs will start with http://
	local prefix = "http"

	-- Screenshots will be called screenshot-namp-<IP>:<port>.png
        local filename = "screenshot-nmap-" .. host.ip .. ":" .. port.number .. ".png"
	
	-- If SSL is set on the port, switch the prefix to https
	if ssl == "ssl" then
		prefix = "https"	
	end

        local answer = http.get(host, port, "/", { bypass_cache = true })

        if answer.status == 401 then
                result = "Page requires authentication (401). Aborting Script"
                return stdnse.format_output(true,  result)
        end

	-- Execute the shell command wkhtmltoimage-i386 <url> <filename>
	local cmd = "wkhtmltoimage-i386 -n " .. prefix .. "://" .. host.ip .. ":" .. port.number .. " " .. filename .. " 2> /dev/null   >/dev/null"
	
	local ret = os.execute(cmd)

	-- If the command was successful, print the saved message, otherwise print the fail message
	local result = "failed (verify wkhtmltoimage-i386 is in your path)"

	if ret then
		result = "Saved to " .. filename
	end

	-- Return the output message
	return stdnse.format_output(true,  result)

end
