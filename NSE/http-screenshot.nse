-- Modified by Travis Lee, 10/21/2014
--  Changed to add option to capture with hostname instead of IP
--  script-args:
--    http-screenshot.usehostname = 1 (default is 0, capture by IP)

-- Modified by Travis Lee, 3/20/2014
--  Changed wkhtmltoimage-i386 to wkhtmltoimage to reflect the new name in new versions
--  Added ability to take script args to adjust format type and quality level.
--  Added default behavior to create an index.html preview file or specify name
--  Added additional checks for open ports before running
--  Added verbose status output
--  script-args:
--    http-screenshot.format = jpg, png, etc (default is jpg)
--    http-screenshot.quality = 0-99 (default is 75)
--    http-screenshot.indexpage = file.html (default is index.html)
--
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

-- Check to see if port is tcp, was scanned, is open, and is likely an http service
portrule = function(host, port)
	local alive = nmap.get_port_state(host, port)

	return alive ~= nil
		and port.protocol == "tcp"
		and port.state == "open"
		and shortport.http
end


action = function(host, port)
	-- HTTP/HTTPS service names
	local svc = { std = { ["http"] = 1, ["http-alt"] = 1 },
	              ssl = { ["https"] = 1, ["https-alt"] = 1 }
	            }
	
	-- Set prefix... Check to see if ssl is enabled, if it is, set prefix to "https", otherwise leave at "http"
	local prefix = "http"
	
	if (svc.ssl[port.service] or port.version.service_tunnel == 'ssl') then
	   	prefix = "https"	
	end
	
	-- Check if the use hostname option is set. If so, set target to hostname instead of ip
	local usehostname = stdnse.get_script_args("http-screenshot.usehostname")
	local target = host.ip
	
	if usehostname then
		if host.name then
			target = host.name
		end
	end

	-- format defaults to jpg
	local format = stdnse.get_script_args("http-screenshot.format") or "jpg"

	-- quality defaults to 75
	local quality = stdnse.get_script_args("http-screenshot.quality") or "75"

	-- quality defaults to index.html
	local indexpage = stdnse.get_script_args("http-screenshot.indexpage") or "index.html"
		
	-- Screenshots will be called screenshot-namp-<IP>:<port>.<format>
    local filename = "screenshot-nmap-" .. target .. "_" .. port.number .. "." .. format
	
	-- Execute the shell command wkhtmltoimage <url> <filename>
	stdnse.print_verbose("http-screenshot.nse: Capturing screenshot for %s",prefix .. "://" .. target .. ":" .. port.number)
	local cmd = "wkhtmltoimage -n --format " .. format .. " --quality " .. quality .. " " .. prefix .. "://" .. target .. ":" .. port.number .. " " .. filename .. " 2> /dev/null   >/dev/null"
	
	local ret = os.execute(cmd)

	-- append to the index html page
	local cmd2 = 'echo "' .. filename .. ':<BR><A HREF=' .. filename .. ' TARGET=_blank><IMG SRC=' .. filename .. ' width=400 border=1></A><BR><BR>" >> ' .. indexpage
	local ret2 = os.execute(cmd2)

	-- If the command was successful, print the saved message, otherwise print the fail message
	local result = "failed (verify wkhtmltoimage is in your path or an xserver is running)"

	if ret then
		result = "Saved to " .. filename
	end

	-- Return the output message
	return stdnse.format_output(true,  result)

end
