local fill
local get
local getString
local resolveNextHeader
local setDefaultNamedArgs
local getVariableLength
local getSubType
local testing


function initHeader(struct)
	local mod = {}
	mod.__index = mod
	
	-- create setter and getter for all members of the defined C struct
	for line in string.gmatch(struct, "(.-)\n") do
		-- get name of member: at the end must be a ';', before that might be [<int>] which is ignored
		local member = string.match(line, "([^%s%[%]]*)%[?%d*%]?%s*;")
		local func_name = member:gsub("^%l", string.upper)
		local type = string.match(line, "%s*(.-)%s+([^%s]*)%s*;")
		if not (member == '') and not (type == '') then 
			-- automatically set byte order for integers
			local conversion = ''
			local close_conversion = ''
			if type == 'uint16_t' then
				conversion = 'hton16('
				close_conversion = ')'
			elseif type == 'uint32_t' then
				conversion = 'hton('
				close_conversion = ')'
			end

			-- set
			local str = [[
return function(self, val)
	val = val or 0
	self.]] .. member .. [[ = ]] .. conversion .. [[val]] .. close_conversion .. [[ 
end]]

			-- load new function and return it
			local func = assert(loadstring(str))()
			mod['set' .. func_name] = func
			
			-- get
			local str = [[
return function(self)
	return ]] .. conversion .. [[self.]] .. member .. close_conversion .. [[ 
end]]

			-- load new function and return it
			local func = assert(loadstring(str))()
			mod['get' .. func_name] = func
			
			-- getFooString
			local str = [[
return function(self)
	return tostring(self:get]] .. func_name .. [[()) 
end]]

			-- load new function and return it
			local func = assert(loadstring(str))()
			mod['get' .. func_name .. 'String'] = func
		else
			print('Warning: empty or malicious line cannot be parsed')
		end
	end

	-- add templates for header-wide functions
	mod.fill = fill 
	mod.get = get 
	mod.getString = getString
	mod.resolveNextHeader = resolveNextHeader
	mod.setDefaultNamedArgs = setDefaultNamedArgs
	mod.getVariableLength = getVariableLength
	mod.getSubType = getSubType
	mod.testing = testing
	
	return setmetatable({}, mod)
end

function fill(self, args, pre)
end

function get(self, pre)
	return {}
end

function getString(self)
	return ""
end

function resolveNextHeader(self)
	return nil
end

function setDefaultNamedArgs(self, pre, namedArgs, nextHeader, accumulatedLength, headerLength)
	return namedArgs
end

function getVariableLength(self)
	return nil
end

function getSubType(self)
	return nil
end
