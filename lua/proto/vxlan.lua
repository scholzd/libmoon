------------------------------------------------------------------------
--- @file vxlan.lua
--- @brief VXLAN utility.
--- Utility functions for the vxlan_header struct
--- Includes:
--- - VXLAN constants
--- - VXLAN header utility
--- - Definition of VXLAN packets
------------------------------------------------------------------------

local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift
local format = string.format

---------------------------------------------------------------------------
---- vxlan constants 
---------------------------------------------------------------------------

local vxlan = {}

vxlan.nextProtocol = {
	ip4 = 0x01,
	ip6 = 0x02,
	eth = 0x03,
	inbt = 0x08
}

---------------------------------------------------------------------------
---- vxlan header
---------------------------------------------------------------------------

vxlan.default = {}

-- definition of the header format
vxlan.default.headerFormat = [[
	uint8_t		flags;
	uint8_t		reserved[3];
	uint8_t		vni[3];
	uint8_t		reserved2;
]]

--- Variable sized member
vxlan.default.headerVariableMember = nil

vxlan.gpe = {}

-- definition of the header format
vxlan.gpe.headerFormat = [[
	uint8_t		flags;
	uint8_t		reserved[2];
	uint8_t		next_protocol;
	uint8_t		vni[3];
	uint8_t		reserved2;
]]

--- Variable sized member
vxlan.gpe.headerVariableMember = nil

vxlan.defaultType = "default"

--- Module for vxlan_header struct
local vxlanHeader = initHeader()
local vxlanGpeHeader = initHeader()
vxlanHeader.__index = vxlanHeader
vxlanGpeHeader.__index = vxlanGpeHeader

--- Set the flags.
--- @param int VXLAN header flags as 8 bit integer.
function vxlanHeader:setFlags(int)
	int = int or 8 -- '00001000'
	self.flags = int
end

vxlanGpeHeader.setFlags = vxlanHeader.setFlags

--- Retrieve the flags.
--- @return Flags as 8 bit integer.
function vxlanHeader:getFlags()
	return self.flags
end

vxlanGpeHeader.getFlags = vxlanHeader.getFlags

--- Retrieve the flags.
--- @return Flags as string.
function vxlanHeader:getFlagsString()
	return format("0x%02x", self:getFlags())
end

vxlanGpeHeader.getFlagsString = vxlanHeader.getFlagsString

--- Set the first reserved field.
--- @param int VXLAN header first reserved field as 24 bit integer.
function vxlanHeader:setReserved(int)
	int = int or 0
	
	-- X 3 2 1 ->  1 2 3
	self.reserved[0] = rshift(band(int, 0xFF0000), 16)
	self.reserved[1] = rshift(band(int, 0x00FF00), 8)
	self.reserved[2] = band(int, 0x0000FF)
end

--- Set the first reserved field.
--- @param int VXLAN header first reserved field as 16 bit integer.
function vxlanGpeHeader:setReserved(int)
	int = int or 0
	
	-- X 2 1 ->  1 2
	self.reserved[0] = rshift(band(int, 0xFF00), 8)
	self.reserved[1] = band(int, 0x00FF)
end

--- Retrieve the first reserved field.
--- @return First reserved field as 24 bit integer.
function vxlanHeader:getReserved()
	return bor(lshift(self.reserved[0], 16), bor(lshift(self.reserved[1], 8), self.reserved[2]))
end

--- Retrieve the first reserved field.
--- @return First reserved field as 16 bit integer.
function vxlanGpeHeader:getReserved()
	return bor(lshift(self.reserved[0], 8), self.reserved[1])
end

--- Retrieve the first reserved field.
--- @return First reserved field as string.
function vxlanHeader:getReservedString()
	return format("0x%06x", self:getReserved())
end

--- Retrieve the first reserved field.
--- @return First reserved field as string.
function vxlanGpeHeader:getReservedString()
	return format("0x%04x", self:getReserved())
end

--- Set the next protocol field
--- @param int next protocol as 8 bit integer
function vxlanGpeHeader:setNextProtocol(int)
	int = int or vxlan.nextProtocol.eth
	self.next_protocol = int
end

--- Get the next protocol field
--- @return next protocol as 8 bit integer
function vxlanGpeHeader:getNextProtocol()
	return self.next_protocol
end

--- Get the next protocol field as string
--- @return next protocol as string
function vxlanGpeHeader:getNextProtocolString()
	val = self:getNextProtocol()
	if val == vxlan.nextProtocol.inbt then
		return "INT"
	else
		return val
	end
end

--- Set the VXLAN network identifier (VNI).
--- @param int VXLAN header VNI as 24 bit integer.
function vxlanHeader:setVNI(int)
	int = int or 0

	-- X 3 2 1 ->  1 2 3
	self.vni[0] = rshift(band(int, 0xFF0000), 16)
	self.vni[1] = rshift(band(int, 0x00FF00), 8)
	self.vni[2] = band(int, 0x0000FF)
end

vxlanGpeHeader.setVNI = vxlanHeader.setVNI

--- Retrieve the VXLAN network identifier (VNI).
--- @return VNI as 24 bit integer.
function vxlanHeader:getVNI()
	return bor(lshift(self.vni[0], 16), bor(lshift(self.vni[1], 8), self.vni[2]))
end

vxlanGpeHeader.getVNI = vxlanHeader.getVNI

--- Retrieve the VXLAN network identifier (VNI).
--- @return VNI as string.
function vxlanHeader:getVNIString()
	return format("0x%06x", self:getVNI())
end

vxlanGpeHeader.getVNIString = vxlanHeader.getVNIString

--- Set the second reserved field.
--- @param int VXLAN header second reserved field as 8 bit integer.
function vxlanHeader:setReserved2(int)
	int = int or 0
	self.reserved2 = int
end

vxlanGpeHeader.setReserved2 = vxlanHeader.setReserved2

--- Retrieve the second reserved field.
--- @return Second reserved field as 8 bit integer.
function vxlanHeader:getReserved2()
	return self.reserved2
end

vxlanGpeHeader.getReserved2 = vxlanHeader.getReserved2

--- Retrieve the second reserved field.
--- @return Second reserved field as string.
function vxlanHeader:getReserved2String()
	return format("0x%02x", self:getReserved2())
end

vxlanGpeHeader.getReserved2String = vxlanHeader.getReserved2String

--- Set all members of the ip header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: Flags, Reserved, VNI, Reserved2
--- @param pre prefix for namedArgs. Default 'vxlan'.
--- @code
--- fill() --- only default values
--- fill{ vxlanFlags=1 } --- all members are set to default values with the exception of vxlanFlags
--- @endcode
function vxlanHeader:fill(args, pre)
	args = args or {}
	pre = pre or "vxlan"
	
	self:setFlags(args[pre .. "Flags"])
	self:setReserved(args[pre .. "Reserved"])
	self:setVNI(args[pre .. "VNI"])
	self:setReserved2(args[pre .. "Reserved2"])
end

--- Set all members of the ip header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: Flags, Reserved, VNI, Reserved2
--- @param pre prefix for namedArgs. Default 'vxlan'.
--- @code
--- fill() --- only default values
--- fill{ vxlanFlags=1 } --- all members are set to default values with the exception of vxlanFlags
--- @endcode
function vxlanGpeHeader:fill(args, pre)
	args = args or {}
	pre = pre or "vxlan"
	
	self:setFlags(args[pre .. "Flags"])
	self:setReserved(args[pre .. "Reserved"])
	self:setNextProtocol(args[pre .. "NextProtocol"])
	self:setVNI(args[pre .. "VNI"])
	self:setReserved2(args[pre .. "Reserved2"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'vxlan'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see vxlanHeader:fill
function vxlanHeader:get(pre)
	pre = pre or "vxlan"

	local args = {}
	args[pre .. "Flags"] = self:getFlags() 
	args[pre .. "Reserved"] = self:getReserved() 
	args[pre .. "VNI"] = self:getVNI() 
	args[pre .. "Reserved2"] = self:getReserved2() 

	return args
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'vxlan'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see vxlanHeader:fill
function vxlanGpeHeader:get(pre)
	pre = pre or "vxlan"

	local args = {}
	args[pre .. "Flags"] = self:getFlags() 
	args[pre .. "Reserved"] = self:getReserved() 
	args[pre .. "NextProtocol"] = self:getNextProtocol() 
	args[pre .. "VNI"] = self:getVNI() 
	args[pre .. "Reserved2"] = self:getReserved2() 

	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function vxlanHeader:getString()
	return "VXLAN flags " .. self:getFlagsString() 
		.. " res " .. self:getReservedString()
		.. " vni " .. self:getVNIString()
		.. " res " .. self:getReserved2String()
end

--- Retrieve the values of all members.
--- @return Values in string format.
function vxlanGpeHeader:getString()
	return "VXLAN flags " .. self:getFlagsString() 
		.. " res " .. self:getReservedString()
		.. " next " .. self:getNextProtocolString()
		.. " vni " .. self:getVNIString()
		.. " res " .. self:getReserved2String()
end

--- Resolve which header comes after this one (in a packet).
--- For instance: in tcp/udp based on the ports.
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'udp', 'icmp', nil)
function vxlanHeader:resolveNextHeader()
	return 'eth'
end	

--- Resolve which header comes after this one (in a packet).
--- For instance: in tcp/udp based on the ports.
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'udp', 'icmp', nil)
function vxlanGpeHeader:resolveNextHeader()
	local type = self:getNextHeader()
	for name, _type in pairs(vxlan.nextHeader) do
		if type == _type then
			return name
		end
	end
	return nil
end	

function vxlanHeader:getSubType()
	if band(self:getFlags(), 0x04) then
		return "gpe"
	else
		return "default"
	end
end

function vxlanGpeHeader:getSubType()
	return "gpe"
end

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

vxlan.default.metatype = vxlanHeader
vxlan.gpe.metatype = vxlanGpeHeader


return vxlan
