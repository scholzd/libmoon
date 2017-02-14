---------------------------------
--- @file packet.lua
--- @brief Utility functions for packets (rte_mbuf).
--- Includes:
--- - General functions (timestamping, rate control, ...)
--- - Offloading
--- - Create packet types
---------------------------------

local ffi = require "ffi"

require "utils"
local dpdkc = require "dpdkc"
local dpdk = require "dpdk"
local log = require "log"
local colors = require "colors"

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift
local istype = ffi.istype
local write = io.write
local strSplit = strSplit

--- Payload type, required by some protocols, defined before loading them
ffi.cdef[[
	union payload_t {
		uint8_t	uint8[0];
		uint16_t uint16[0];
		uint32_t uint32[0];
		uint64_t uint64[0];
	};
]]

local proto = require "proto.proto"

-------------------------------------------------------------------------------------------
---- General functions
-------------------------------------------------------------------------------------------

--- Module for packets (rte_mbuf)
local pkt = {}
pkt.__index = pkt


--- Get a void* pointer to the packet data.
function pkt:getData()
	return ffi.cast("void*", ffi.cast("uint8_t*", self.buf_addr) + self.data_off)
end

function pkt:getBytes()
	return ffi.cast("uint8_t*", self.buf_addr) + self.data_off
end

function pkt:getTimesync()
	return self.timesync
end

function pkt:dumpFlags()
	log:debug(tostring(self.ol_flags) .. " " .. tostring(self.tx_offload))
end

--- Retrieve the time stamp information.
--- @return The timestamp or nil if the packet was not time stamped.
function pkt:getTimestamp()

	if bit.bor(self.ol_flags, dpdk.PKT_RX_IEEE1588_TMST) ~= 0 then
		-- TODO: support timestamps that are stored in registers instead of the rx buffer
		local data = ffi.cast("uint32_t* ", self:getData())
		-- TODO: this is only tested with the Intel 82580 NIC at the moment
		-- the datasheet claims that low and high are swapped, but this doesn't seem to be the case
		-- TODO: check other NICs
		local low = data[2]
		local high = data[3]
		return high * 2^32 + low
	end
end

--- Check if the PKT_RX_IEEE1588_TMST flag is set.
--- Turns out that this flag is pretty pointless, it does not indicate
--- if the packet was actually timestamped, just that it came from a
--- queue/filter with timestamping enabled.
--- You probably want to use device:hasTimestamp() and check the sequence number.
function pkt:hasTimestamp()
	return bit.bor(self.ol_flags, dpdk.PKT_RX_IEEE1588_TMST) ~= 0
end

function pkt:getSecFlags()
	local secp = bit.rshift(bit.band(self.ol_flags, dpdk.PKT_RX_IPSEC_SECP), 11)
	local secerr = bit.rshift(bit.band(self.ol_flags, bit.bor(dpdk.PKT_RX_SECERR_MSB, dpdk.PKT_RX_SECERR_LSB)), 12)
	return secp, secerr
end

--- Offload VLAN tagging to the NIC for this packet.
function pkt:setVlan(vlan, pcp, cfi)
	local tci = vlan + bit.lshift(pcp or 0, 13) + bit.lshift(cfi or 0, 12)
	self.vlan_tci = tci
	self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_VLAN_PKT)
end

local VLAN_VALID_MASK = bit.bor(dpdk.PKT_RX_VLAN_PKT, dpdk.PKT_TX_VLAN_PKT)

--- Get the VLAN associated with a received packet.
function pkt:getVlan()
	if bit.bor(self.ol_flags, VLAN_VALID_MASK) == 0 then
		return nil
	end
	local tci = self.vlan_tci
	return bit.band(tci, 0xFFF), bit.rshift(tci, 13), bit.band(bit.rshift(tci, 12), 1)
end


--- @todo TODO does
function pkt:setSize(size)
	self.pkt_len = size
	self.data_len = size
end

function pkt:getSize()
	return self.pkt_len
end

--- Returns the packet data cast to the best fitting packet struct. 
--- Starting with ethernet header.
--- @return packet data as cdata of best fitting packet
function pkt:get()
	return self:getEthernetPacket():resolveLastHeader()
end

--- Dumps the packet data cast to the best fitting packet struct.
--- @param bytes number of bytes to dump, optional (default = packet size)
--- @param stream the stream to write to, optional (default = io.stdout)
--- @param colorized Print the dump with different colors for each protocol (default = true)
function pkt:dump(bytes, stream, colorized)
	if type(bytes) == "userdata" then
		stream = bytes
		colorized = stream
		bytes = nil
	end
	colorized = colorized == nil or colorized
	self:get():dump(bytes or self.pkt_len, stream or io.stdout, colorized)
end

function pkt:free()
	dpdkc.rte_pktmbuf_free_export(self)
end

-------------------------------------------------------------------------------------------------------
---- IPSec offloading
-------------------------------------------------------------------------------------------------------

--- Use IPsec offloading.
--- @param idx SA_IDX to use
--- @param sec_type IPSec type to use ("esp"/"ah")
--- @param esp_mode ESP mode to use encrypt(1) or authenticate(0)
function pkt:offloadIPSec(idx, sec_type, esp_mode)
	local mode = esp_mode or 0
	local t = nil
	if sec_type == "esp" then
		t = 1
	elseif sec_type == "ah" then
		t = 0
	else
		log:fatal("Wrong IPSec type (esp/ah)")
	end

	-- Set IPSec offload flag in advanced data transmit descriptor.
	self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPSEC)

	-- Set 10 bit SA_IDX
	--if idx < 0 or idx > 1023 then
	--	error("SA_IDX has to be in range 0-2013")
	--end
	--self.ol_ipsec.sec.sa_idx = idx
	self.ol_ipsec.data = bit.bor(self.ol_ipsec.data, bit.lshift(bit.band(idx, 0x3FF), 0))

	-- Set ESP enc/auth mode
	--if mode ~= 0 and mode ~= 1 then
	--	error("Wrong IPSec mode")
	--end
	--self.ol_ipsec.sec.mode = mode
	self.ol_ipsec.data = bit.bor(self.ol_ipsec.data, bit.lshift(bit.band(mode, 0x1), 20))

	-- Set IPSec ESP/AH type
	--if sec_type == "esp" then
	--	self.ol_ipsec.sec.type = 1
	--elseif sec_type == "ah" then
	--	self.ol_ipsec.sec.type = 0
	--else
	--	error("Wrong IPSec type (esp/ah)")
	--end
	self.ol_ipsec.data = bit.bor(self.ol_ipsec.data, bit.lshift(bit.band(t, 0x1), 19))
end

--- Set the ESP trailer length
--- @param len ESP Trailer length in bytes
function pkt:setESPTrailerLength(len)
	--Disable range check for performance reasons
	--if len < 0 or len > 511 then
	--	error("ESP trailer length has to be in range 0-511")
	--end
	--self.ol_ipsec.sec.esp_len = len -- dont use bitfields
	self.ol_ipsec.data = bit.bor(self.ol_ipsec.data, bit.lshift(bit.band(len, 0x1FF), 10))
end

-------------------------------------------------------------------------------------------------------
---- Checksum offloading
-------------------------------------------------------------------------------------------------------

--- Instruct the NIC to calculate the IP checksum for this packet.
--- @param ipv4 Boolean to decide whether the packet uses IPv4 (set to nil/true) or IPv6 (set to anything else).
--- 			   In case it is an IPv6 packet, do nothing (the header has no checksum).
--- @param l2Len Length of the layer 2 header in bytes (default 14 bytes for ethernet).
--- @param l3Len Length of the layer 3 header in bytes (default 20 bytes for IPv4).
function pkt:offloadIPChecksum(ipv4, l2Len, l3Len)
	ipv4 = ipv4 == nil or ipv4
	l2Len = l2Len or 14
	if ipv4 then
		l3Len = l3Len or 20
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV4, dpdk.PKT_TX_IP_CKSUM)
	else
		l3Len = l3Len or 40
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV4, dpdk.PKT_TX_IP_CKSUM)
	end
	self.tx_offload = l2Len + l3Len * 128
end

--- Instruct the NIC to calculate the IP and UDP checksum for this packet.
--- @param ipv4 Boolean to decide whether the packet uses IPv4 (set to nil/true) or IPv6 (set to anything else).
--- @param l2Len Length of the layer 2 header in bytes (default 14 bytes for ethernet).
--- @param l3Len Length of the layer 3 header in bytes (default 20 bytes for IPv4, 40 bytes for IPv6).
function pkt:offloadUdpChecksum(ipv4, l2Len, l3Len)
	-- NOTE: this method cannot be moved to the udpPacket class because it doesn't (and can't) know the pktbuf it belongs to
	ipv4 = ipv4 == nil or ipv4
	l2Len = l2Len or 14
	if ipv4 then
		l3Len = l3Len or 20
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV4, dpdk.PKT_TX_IP_CKSUM, dpdk.PKT_TX_UDP_CKSUM)
		self.tx_offload = l2Len + l3Len * 128
		-- calculate pseudo header checksum because the NIC doesn't do this...
		dpdkc.calc_ipv4_pseudo_header_checksum(self:getData(), 20)
	else 
		l3Len = l3Len or 40
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV6, dpdk.PKT_TX_IP_CKSUM, dpdk.PKT_TX_UDP_CKSUM)
		self.tx_offload = l2Len + l3Len * 128
		-- calculate pseudo header checksum because the NIC doesn't do this...
		dpdkc.calc_ipv6_pseudo_header_checksum(self:getData(), 30)
	end
end

--- Instruct the NIC to calculate the IP and TCP checksum for this packet.
--- @param ipv4 Boolean to decide whether the packet uses IPv4 (set to nil/true) or IPv6 (set to anything else).
--- @param l2Len Length of the layer 2 header in bytes (default 14 bytes for ethernet).
--- @param l3Len Length of the layer 3 header in bytes (default 20 bytes for IPv4, 40 bytes for IPv6).
function pkt:offloadTcpChecksum(ipv4, l2Len, l3Len)
	-- NOTE: this method cannot be moved to the udpPacket class because it doesn't (and can't) know the pktbuf it belongs to
	ipv4 = ipv4 == nil or ipv4
	l2Len = l2Len or 14
	if ipv4 then
		l3Len = l3Len or 20
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV4, dpdk.PKT_TX_IP_CKSUM, dpdk.PKT_TX_TCP_CKSUM)
		self.tx_offload = l2Len + l3Len * 128
		-- calculate pseudo header checksum because the NIC doesn't do this...
		dpdkc.calc_ipv4_pseudo_header_checksum(self:getData(), 25)
	else 
		l3Len = l3Len or 40
		self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IPV6, dpdk.PKT_TX_IP_CKSUM, dpdk.PKT_TX_TCP_CKSUM)
		self.tx_offload = l2Len + l3Len * 128
		-- calculate pseudo header checksum because the NIC doesn't do this...
		dpdkc.calc_ipv6_pseudo_header_checksum(self:getData(), 35)
	end
end

--- @todo TODO docu
function pkt:enableTimestamps()
	self.ol_flags = bit.bor(self.ol_flags, dpdk.PKT_TX_IEEE1588_TMST)
end


----------------------------------------------------------------------------------
---- Create new stack type
----------------------------------------------------------------------------------

-- functions of the stack
local stackGetHeaders
local stackGetHeader
local stackDump
local stackFill
local stackGet
local stackResolveLastHeader
local stackCalculateChecksums
local stackMakeStruct
local stackMatchesStack
local stackAdjustStack

--- Create struct and functions for a new stack.
--- For implemented headers (see proto/) these packets are defined in the section 'Packet struct' of each protocol file
--- @param args list of keywords (see makeStruct)
--- @return returns the constructor/cast function for this stack
--- @see stackMakeStruct
function createStack(...)
	local args = {...}
	
	local stack = {}
	stack.__index = stack
	local noPayload = args[#args] == "noPayload"
	if noPayload then
		args[#args] = nil
	end
	-- create struct
	local stackName, ctype = stackMakeStruct(args, noPayload)
	if not stackName then
		log:warn("Failed to create new stack type.")
		return
	end
	if not ctype then
		log:warn("Stack already exists, only returning cast")
		return function(self) return stackName(self:getData()) end
	end

	-- cache of structs with varying length members for this stack
	local cache = {}

	-- functions of the stack
	stack.getArgs = function() return args end
	
	stack.getName = function() return stackName end
	
	stack.getCache = function() return cache end

	stack.addToCache = function(self, index, obj) cache[index] = obj end

	stack.dumpCache = function()
		print('--------------dumping cache-----------------')
		for k, v in pairs(cache) do
			print(tostring(k) .. ' ==== ' .. tostring(v))
		end
	end

	stack.getHeaders = stackGetHeaders

	stack.getHeader = stackGetHeader 

	stack.dump = stackDump
	
	stack.fill = stackFill

	stack.get = stackGet

	stack.resolveLastHeader = stackResolveLastHeader

	stack.matchesStack = stackMatchesStack(args)

	stack.adjustStack = stackAdjustStack(args, stackName)

	-- runtime critical function, load specific code during runtime
	stack.setLength = stackSetLength(args)

	-- functions for manual (not offloaded) checksum calculations
	-- runtime critical function, load specific code during runtime
	stack.calculateChecksums = stackCalculateChecksums(args)
	
	for _, v in ipairs(args) do
		local data = getHeaderData(v)
		header = data['proto']
		member = data['name']
		-- if the header has a checksum, add a function to calculate it
		if header == "ip4" or header == "icmp" then -- FIXME NYI or header == "udp" or header == "tcp" then
			local key = 'calculate' .. member:gsub("^.", string.upper) .. 'Checksum'
			stack[key] = function(self) self:getHeader(v):calculateChecksum() end
		end
	end


	-- add functions to stack
	ffi.metatype(stackName, stack)

	-- return 'get'/'cast' for this kind of stack
	return function(self) return ctype(self:getData()) end
end

function stackCreate(...)
	log:warn('This function is deprecated and will be removed in the future.')
	log:warn('Renamed to createStack(...)')
	return createStack(...)
end

--- Get the name of the header, the name of the respective member and the length of the variable member
--- @param v Either the name of the header (then the member has the same name), or a table { header, name = member, length = length, subType = type }
--- @return Table with all data: { proto = header, name = member, length = length, subType = type }
function getHeaderData(v)
	if not v then
		return
	elseif type(v) == "table" then
		local header = v[1]
		local member = v['name']
		local subType
		member = member or header
		if proto[header].defaultType then
			subType = subType or proto[header].defaultType
		end
		return { proto = header, name = member, length = v['length'], subType = v['subType'] or subType }
	else
		-- only the header name is given -> member has same name, no variable length
		-- set default subtype if available
		local subType
		if proto[v].defaultType then
			subType = subType or proto[v].defaultType
		end
		-- otherwise header name = member name
		return { proto = v, name = v, length = nil, subType = subType }
	end
end

--- Get all headers of a stack as list.
--- @param self The stack
--- @return Table of members of the stack
function stackGetHeaders(self) 
	local headers = {} 
	for i, v in ipairs(self:getArgs()) do 
		headers[i] = stackGetHeader(self, v) 
	end 
	return headers 
end

--- Get the specified header of a stack (e.g. self.eth).
--- @param self the stack (cdata)
--- @param h header to be returned
--- @return The member of the stack
function stackGetHeader(self, h)
	local member = getHeaderData(h)['name']
	return self[member]
end

--- Print a hex dump of a stack.
--- @param self the stack
--- @param bytes Number of bytes to dump. If no size is specified the payload is truncated.
--- @param stream the IO stream to write to, optional (default = io.stdout)
--- @param colorized Dump the stack colorized, every protocol in a different color (default = true)
function stackDump(self, bytes, stream, colorized) 
	if type(bytes) == "userdata" then
		-- if someone calls this directly on a stack
		stream = bytes
		bytes = nil
	end
	bytes = bytes or ffi.sizeof(self:getName())
	stream = stream or io.stdout
	colorized = colorized == nil or colorized

	-- print timestamp
	stream:write(colorized and white(getTimeMicros()) or getTimeMicros())

	-- separators (protocol offsets) for colorized hex dump
	local seps = { }
	local colorCode = ''
	-- headers in cleartext
	for i, v in ipairs(self:getHeaders()) do
		if colorized then
			colorCode = getColorCode(i)
		end

		local str = v:getString()
		if i == 1 then
			stream:write(colorCode .. " " .. str .. "\n")
		else
			stream:write(colorCode .. str .. "\n")
		end
		seps[#seps + 1] = (seps[#seps] or 0 ) + ffi.sizeof(v)
	end

	-- hex dump
	dumpHex(self, bytes, stream, colorized and seps or nil)
end

--- Set all members of all headers.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- The argument 'pktLength' can be used to automatically calculate and set the length member of headers (e.g. ip header).
--- @code 
--- fill() --- only default values
--- fill{ ethSrc="12:23:34:45:56:67", ipTTL=100 } --- all members are set to default values with the exception of ethSrc and ipTTL
--- fill{ pktLength=64 } --- only default values, length members of the headers are adjusted
--- @endcode
--- @param self The stack
--- @param args Table of named arguments. For a list of available arguments see "See also"
--- @note This function is slow. If you want to modify members of a header during a time critical section of your script use the respective setters.
function stackFill(self, namedArgs) 
	namedArgs = namedArgs or {}
	local headers = self:getHeaders()
	local args = self:getArgs()
	local accumulatedLength = 0
	for i, v in ipairs(headers) do
		local curMember = getHeaderData(args[i])['name']
		local nextHeader = getHeaderData(args[i + 1])
		nextHeader = nextHeader and nextHeader['proto']
		
		namedArgs = v:setDefaultNamedArgs(curMember, namedArgs, nextHeader, accumulatedLength, ffi.sizeof(v))
		v:fill(namedArgs, curMember) 

		accumulatedLength = accumulatedLength + ffi.sizeof(v)
	end
end

--- Retrieve the values of all members as list of named arguments.
--- @param self The stack
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see stackFill
function stackGet(self) 
	local namedArgs = {} 
	local args = self:getArgs()
	for i, v in ipairs(self:getHeaders()) do 
		local member = getHeaderData(args[i])['name']
		namedArgs = mergeTables(namedArgs, v:get(member)) 
	end 
	return namedArgs 
end

--- Try to find out what the next header in the payload of this stack is.
--- This function is only used for buf:get/buf:dump
--- @param self The stack
function stackResolveLastHeader(self)
	local name = self:getName()
	local headers = self:getHeaders()

	-- do we have struct with correct sub-type?
	local subType = headers[#headers]:getSubType()
	if subType then
		local sub = strSplit(name, "_")
		if sub[#sub] ~= subType then
			sub[#sub] = subType
			
			local newName = table.concat(sub, "_")
			return ffi.cast(newName .. "*", self):resolveLastHeader()
		end
	end

	-- do we have struct with correct header length?
	local len = headers[#headers]:getVariableLength() 
	if len and len > 0 then	
		local sub = strSplit(name, "_")
		local l = sub[#sub - 1]
		if len ~= l then
			local newArgs = self:getArgs()
			local last = newArgs[#newArgs]
			if type(last) == "string" then
				newArgs[#newArgs] = { last, last, length = len}
			else
				newArgs[#newArgs]["length"] = len
			end
			pkt.TMP_STACK = createStack(unpack(newArgs))
			-- build name with len adjusted
			sub[#sub - 1] = len
			local newName = table.concat(sub, "_")
			if name ~= newName then
				return ffi.cast(newName .. "*", self):resolveLastHeader()
			end
		end
	end	
	local nextHeader = headers[#headers]:resolveNextHeader()

	-- unable to resolve: either there is no next header, or libmoon does not support it yet
	-- either case, we stop and return current type of stack
	if not nextHeader then
		return self
	else
		local newName, nextMember
		local next = getHeaderData(nextHeader)
		nextHeader = next['proto']
		nextMember = next['name']
		nextSubType = next['subType']
		nextLength = next['length']
		-- we know the next header, append it
		name = name .. "__" .. nextHeader

		-- if simple struct (headername = membername) already exists we can directly cast
		--nextMember = nextHeader
		newName = name .. nextMember .. "_x_" .. (nextSubType or "x")

		if not pkt.stackStructs[newName] then
			-- check if a similar struct with this header order exists
			newName = name
			local found = nil
			for k, v in pairs(pkt.stackStructs) do
				if string.find(k, newName) and not string.find(string.gsub(k, newName, ""), "__") then
					-- the type matches and there are no further headers following (which would have been indicated by another "__")
					found = k
					break
				end
			end
			if found then
				newName = found
			else
				-- last resort: build new stack type. However, one has to consider that one header 
				-- might occur multiple times! In this case the member must get a new (unique!) name.
				local args = self:getArgs()
				local newArgs = {}
				local counter = 1
				local newMember = nextMember
				-- build new args information and in the meantime check for duplicates
				for i, v in ipairs(args) do
					data = getHeaderData(v)
					header = data['proto']
					member = data['name']
					if member == newMember then
						-- found duplicate, increase counter for newMember and keep checking for this one now
						counter = counter + 1
						newMember = nextMember .. "" .. counter
					end
					newArgs[i] = v
				end

				-- add new header and member
				newArgs[#newArgs + 1] = { nextHeader, name = newMember, subType = nextSubType, length = nextLength }

				-- create new stack. It is unlikely that exactly this stack type with this made up naming scheme will be used
				-- Therefore, we don't really want to "safe" the cast function
				pkt.TMP_STACK = createStack(unpack(newArgs))
				
				-- name of the new stack type
				newName = newName .. '_' .. newMember .. '_x_' .. (nextSubType or 'x')
			end
		end

		-- finally, cast the stack to the next better fitting stack type and continue resolving
		return ffi.cast(newName .. "*", self):resolveLastHeader()
	end
end

--- Set length for all headers.
--- Necessary when sending variable sized packets.
--- @param self The stack
--- @param length Length of the packet. Value for respective length member of headers get calculated using this value.
function stackSetLength(args)
	local str = ""
	-- build the setLength functions for all the headers in this stack type
	local accumulatedLength = 0
	for _, v in ipairs(args) do
		local data = getHeaderData(v)
		header = data['proto']
		member = data['name']
		subType = data['subType']
		header = subType and header .. "_" .. subType or header
		if header == "ip4" or header == "udp" or header == "ptp" or header == "ipfix" then
			str = str .. [[
				self.]] .. member .. [[:setLength(length - ]] .. accumulatedLength .. [[)
				]]
		elseif header == "ip6" then
			str = str .. [[
				self.]] .. member .. [[:setLength(length - ]] .. accumulatedLength + 40 .. [[)
				]]
		end
		accumulatedLength = accumulatedLength + ffi.sizeof("struct " .. header .. "_header")
	end

	-- build complete function
	str = [[
		return function(self, length)]] 
			.. str .. [[
		end]]

	-- load new function and return it
	local func = assert(loadstring(str))()

	return func
end

--- Calculate all checksums manually (not offloading them).
--- There also exist functions to calculate the checksum of only one header.
--- Naming convention: pkt:calculate<member>Checksum() (for all existing stacks member = {Ip, Tcp, Udp, Icmp})
--- @note Calculating checksums manually is extremely slow compared to offloading this task to the NIC (~65% performance loss at the moment)
--- @todo Manual calculation of udp and tcp checksums NYI
function stackCalculateChecksums(args)
	local str = ""
	for _, v in ipairs(args) do
		local data = getHeaderData(v)
		header = data['proto']
		member = data['name']
		
		-- if the header has a checksum, call the function
		if header == "ip4" or header == "icmp" then -- FIXME NYI or header == "udp"
			str = str .. [[
				self.]] .. member .. [[:calculateChecksum()
				]]
		elseif header == "tcp" then
			str = str .. [[
				self.]] .. member .. [[:calculateChecksum(data, len, ipv4)
				]]
		end
	end
	
	-- build complete function
	str = [[
		return function(self, data, len, ipv4)]] 
			.. str .. [[
		end]]
	
	-- load new function and return it
	local func = assert(loadstring(str))()

	return func
end

function stackMatchesStack(args)
	local str = ""
	local nextHeader = nil
	local first = true
	for i, v in ipairs(args) do
		local proto = getHeaderData(args[i])
		local name = proto['name']
		local subType = proto['subType']
		if not nextHeader then
			nextHeader = [[self.]] .. name .. [[:resolveNextHeader()]]
			if subType then
				str = str .. [[
(self.]] .. name .. [[:getSubType() == ']] .. subType .. [[') 
]]
				first = false
			end
		else
			if not first then
				str = str .. '		and '
			end
			first = false
			str = str .. [[
(self.]] .. name .. [[:getHeaderType() == ]] .. nextHeader .. [[) 
]]
			if subType then
				str = str .. [[
and (self.]] .. name .. [[:getSubType() == ']] .. subType .. [[') 
]]
			end
			nextHeader = [[self.]] .. name .. [[:resolveNextHeader()]]
		end
	end

	if str == '' then
		str = 'true'
	end

	str = [[
return function(self) 
	return ]] .. str .. [[ 
end]]
	
	-- load new function and return it
	local func = assert(loadstring(str))()

	return func
end

function stackAdjustStack(args, stackName)
	local str = ""
	local lengthMems = ''
	local argss = ''
	local first = true
	local lengthParams = {}

	-- serialize the args
	for i, v in ipairs(args) do
		-- if its only the header name, wrap it
		if type(v) ~= 'table' then
			v = { v }
		end
		-- special treatment for var length headers
		if proto[getHeaderData(v)['proto']].headerVariableMember then
			local name = 'length' .. i
			lengthParams[name] = v['length'] or 0
			v['length'] = name
		end
		if not first then
			argss = argss .. ','
		end
		first = false
		argss = argss .. '{'
		local f = true
		-- serialize this header data
		for k, val in pairs(v) do
			if not f then
				argss = argss .. ','
			end
			f = false
			if k == 'length' then
				argss = argss .. k .. '=' .. val
			elseif type(k) ~= 'number' then
				argss = argss .. k .. '="' .. val .. '"'
			else
				argss = argss .. '"' .. val .. '"'
			end
		end
		argss = argss .. '}'
	end

	-- init length values string
	local initLength = ''
	local index = ''
	local first = true
	local i = 0
	for length, val in pairs(lengthParams) do
		initLength = initLength .. [[	local ]] .. length .. [[ = ]] .. val .. [[ 
]]
		if not first then
			index = index .. ' + '
		end
		index = index .. length
		if not first then
			index = index .. ' * ' .. tostring(256 * i)
		end
		first = false
		i = i + 1
	end


	for i, v in ipairs(args) do
		local p = getHeaderData(args[i])
		local prot = p['proto']
		local name = p['name']
		local subType = p['subType']
		if proto[prot].headerVariableMember then
			lengthMems = lengthMems .. ', length' .. i
			str = str .. [[
	local length]] .. i .. [[ = self.]] .. name .. [[:getVariableLength() 
	-- calculate index
	local index = ]] .. index .. [[ 
	local newStack = cache[index]
	if not newStack then
		-- need to generate this particular stack once
		newStack = createStack(]] .. argss .. [[)
		origSelf:addToCache(index, newStack)
	end
	self = newStack(buf)
	--self:dump()
]]
		end
	end

	str = [[
return function(origSelf, buf) 
	-- get the cache for this stack
	local cache = origSelf:getCache()
	-- we want to always keep the cache of the original stack
	local self = origSelf

	-- all length members in this stack initialized 
]] .. initLength .. [[ 

]] .. str .. [[	return self
end]]
	--print(str)	
	-- load new function and return it
	local func = assert(loadstring(str))()

	return func
end


local createdHeaderStructs = {}

local headerStructTemplate = [[
	struct __attribute__((__packed__)) NAME {
MEMBER};]]

local function defineHeaderStruct(p, subType, size)
	local name = p .. (subType and "_" .. subType or "") .. "_header" .. (size and "_" .. size or "")

	-- check whether it already ecists
	if createdHeaderStructs[name] then
		log:debug("Header struct " .. name .. " already exists, skipping.")
		return name
	end

	-- build struct from template and proto header format
	local str = headerStructTemplate
	if proto[p].defaultType then
		subType = subType or proto[p].defaultType
	end
	str = string.gsub(str, "MEMBER", (subType and proto[p][subType].headerFormat or proto[p].headerFormat))

	-- set size of variable sized member
	if proto[p].headerVariableMember then
		local member = (subType and proto[p][subType].headerVariableMember or proto[p].headerVariableMember) .. "%["
		str = string.gsub(str, member, member .. (size or 0))
	end
	
	-- build the name
	str = string.gsub(str, "NAME", name)

	-- define and add header related functions
	ffi.cdef(str)
	ffi.metatype("struct " .. name, (subType and proto[p][subType].metatype or proto[p].metatype))
	log:debug("Created " .. name)

	-- add to list of already created header structs
	createdHeaderStructs[name] = true

	-- return name used to generate stack
	return name	
end

--- Table that contains the names and args of all created stack structs
pkt.stackStructs = {}

-- List all created stack structs enlisted in stackStructs
-- Debugging function
function listStackStructs()
	printf("All available stack structs:")
	for k, v in pairs(pkt.stackStructs) do
		printf(k)
	end
end

--- Creates a stack struct (cdata) consisting of different headers.
--- Simply list the headers in the order you want them to be in a stack.
--- If you want the member to be named differently, use the following syntax:
--- normal: <header> ; different membername: { <header>, <member> }.
--- Supported keywords: eth, arp, ptp, ip, ip6, udp, tcp, icmp
--- @code
--- makeStruct('eth', { 'ip4', 'ip' }, 'udp') --- creates an UDP stack struct
--- --- the ip4 member of the stack is named 'ip'
--- @endcode
--- The name of the created (internal) struct looks as follows: 
--- struct __HEADER1_MEMBER1__HEADER2_MEMBER2 ... 
--- Only the "__" (double underscore) has the special meaning of "a new header starts with name 
--- <everything until "_" (single underscore)>, followed by the member name <everything after "_" 
--- until next header starts (indicated by next __)>"
--- @param args list of keywords/tables of keyword-member pairs
--- @param noPayload do not append payload VLA
--- @return name name of the struct
--- @return ctype ctype of the struct
function stackMakeStruct(args, noPayload)
	local name = ""
	local str = ""

	local members = {}

	-- add the specified headers and build the name
	for _, v in ipairs(args) do
		local data = getHeaderData(v)
		header = data['proto']
		member = data['name']
		length = data['length']
		subType = data['subType']

		-- check for duplicate member names as ffi does not crash (it is mostly ignored)
		if members[member] then
			log:fatal("Member within this struct has same name: %s \n%s", member, str)
		end
		members[member] = true

		local headerStruct = defineHeaderStruct(header, subType, length)

		-- add header
		str = str .. [[
		struct ]] .. headerStruct .. ' ' .. member .. [[;
		]]

		-- build name
		name = name .. "__" .. header .. "_" .. member .. "_" .. (length or "x") .. "_" .. (subType or "x")
	end

	-- handle raw stack
	if name == "" then
		name = "raw"
	end

	-- add rest of the struct
	str = [[
	struct __attribute__((__packed__)) ]] 
	.. name 
	.. [[ {
		]]
	.. str 
	.. (not noPayload and [[
		union payload_t payload;
	]] or "")
	..	"};"

	name = "struct " .. name

	-- check uniqueness of stack type (name of struct)
	if pkt.stackStructs[name] then
		log:warn("Struct with name \"" .. name .. "\" already exists. Skipping.")
		return ffi.typeof(name .. "*")
	else
		
		-- add to list of existing structs
		pkt.stackStructs[name] = {args}

		log:debug("Created struct %s", name)
		log:debug("%s", str)
		
		-- add struct definition
		ffi.cdef(str)

		-- return full name and typeof
		return name, ffi.typeof(name .. "*")
	end
end

--! Setter for raw packets
--! @param data: raw packet data
function pkt:setRawPacket(data)
	self:setSize(#data)
	ffi.copy(self:getData(), data)
end

---------------------------------------------------------------------------
---- Metatypes
---------------------------------------------------------------------------

ffi.metatype("struct rte_mbuf", pkt)


---------------------------------------------------------------------------
---- Protocol Stacks
---------------------------------------------------------------------------

pkt.getRawPacket = createStack()

pkt.getEthernetPacket = createStack("eth")
pkt.getEthPacket = pkt.getEthernetPacket
pkt.getEthernetVlanPacket = createStack({"eth", subType = "vlan"})
pkt.getEthVlanPacket = pkt.getEthernetVlanPacket

pkt.getIP4Packet = createStack("eth", "ip4") 
pkt.getIP6Packet = createStack("eth", "ip6")
pkt.getIPPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getIP4Packet(self) 
	else 
		return pkt.getIP6Packet(self) 
	end 
end   

pkt.getArpPacket = createStack("eth", "arp")

pkt.getIcmp4Packet = createStack("eth", "ip4", "icmp")
pkt.getIcmp6Packet = createStack("eth", "ip6", "icmp")
pkt.getIcmpPacket = function(self, ip4)
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getIcmp4Packet(self) 
	else 
		return pkt.getIcmp6Packet(self) 
	end 
end   

pkt.getUdp4Packet = createStack("eth", "ip4", "udp")
pkt.getUdp6Packet = createStack("eth", "ip6", "udp") 
pkt.getUdpPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getUdp4Packet(self) 
	else 
		return pkt.getUdp6Packet(self)
	end 
end   

pkt.getTcp4Packet = createStack("eth", "ip4", "tcp")
pkt.getTcp6Packet = createStack("eth", "ip6", "tcp")
pkt.getTcpPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getTcp4Packet(self) 
	else 
		return pkt.getTcp6Packet(self) 
	end 
end   

pkt.getPtpPacket = createStack("eth", "ptp")
pkt.getUdpPtpPacket = createStack("eth", "ip4", "udp", "ptp")

pkt.getVxlanPacket = createStack("eth", "ip4", "udp", "vxlan")
pkt.getVxlanEthernetPacket = createStack("eth", "ip4", "udp", "vxlan", { "eth", name = "innerEth" })

pkt.getEsp4Packet = createStack("eth", "ip4", "esp")
pkt.getEsp6Packet = createStack("eth", "ip6", "esp") 
pkt.getEspPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getEsp4Packet(self) 
	else 
		return pkt.getEsp6Packet(self) 
	end 
end

pkt.getAH4Packet = createStack("eth", "ip4", "ah")
pkt.getAH6Packet = nil --createStack("eth", "ip6", "ah6") --TODO: AH6 needs to be implemented
pkt.getAHPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getAH4Packet(self) 
	else 
		return pkt.getAH6Packet(self) 
	end 
end

pkt.getDns4Packet = createStack('eth', 'ip4', 'udp', 'dns')
pkt.getDns6Packet = createStack('eth', 'ip6', 'udp', 'dns')
pkt.getDnsPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getDns4Packet(self) 
	else 
		return pkt.getDns6Packet(self) 
	end 
end

pkt.getSFlowPacket = createStack("eth", "ip4", "udp", {"sflow", subType = "ip4"}, "noPayload")

pkt.getIpfixPacket = createStack("eth", "ip4", "udp", "ipfix")

pkt.getLacpPacket = createStack('eth', 'lacp')


return pkt
