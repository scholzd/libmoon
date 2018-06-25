------------------------------------------------------------------------
--- @file int.lua
--- @brief (int) utility.
--- Utility functions for the int_header structs 
--- Includes:
--- - int constants
--- - int header utility
--- - Definition of int packets
------------------------------------------------------------------------

local ffi = require "ffi"
local log = require "log"
require "proto.template"
local initHeader = initHeader

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift


---------------------------------------------------------------------------
---- int constants 
---------------------------------------------------------------------------

--- int protocol constants
local mod = {}


---------------------------------------------------------------------------
---- int header + int shim header over vxlan
---------------------------------------------------------------------------
--- ---First 8b Ver_rep
--- 4b Version
--- 2b Replication
--- 1b Copy
--- 1b Max Hop Count exceeded
--- ---Second/third 8b
--- 1b MTU exceeded
--- 10b Reserved
--- 5b Hop ML - Per Hop Metadata Length
mod.headerFormat = [[
	uint8_t		type;
	uint8_t		reserved0;
	uint8_t		length;
	uint8_t		nextProtocol;
	uint8_t		ver_rep;
	uint8_t 	byte2;
	uint8_t 	byte3;
	uint8_t 	remainingHopCount;
	uint16_t	instructionBitmap;
	uint16_t	reserved2;
	uint32_t	metadata[];
]]

--- Variable sized member
mod.headerVariableMember = "metadata"

--- Module for int_address struct
local intHeader = initHeader(mod.headerFormat)
intHeader.__index = intHeader
	
-- version | replication | copy | exceeded | reserved | inst cnt
-- XXYYCERR RRRZZZZZ


----------------------------------------------------------
--- First 8 Bit Field ver_rep
----------------------------------------------------------
--- Set the version.
--- @param int version of the int header as 4 bit integer.
function intHeader:setVersion(int)
	int = int or 1
	int = band(lshift(int, 4), 0xf0) -- fill to 8 bits
	
	old = self.ver_rep
	old = band(old, 0x0f) -- remove old value
	
	val = bor(old, int)
	self.ver_rep = val
end

--- Retrieve the version.
--- @return version as 4 bit integer.
function intHeader:getVersion()
	return band(rshift(self.ver_rep, 4), 0x0f)
end

function intHeader:getVersionString()
	return self:getVersion()
end

--- Set the replication.
--- @param int replication of the int header as 2 bit integer.
function intHeader:setReplication(int)
	int = int or 0
	int = band(lshift(int, 2), 0x0c) -- fill to 8 bits
	--1100
	old = self.ver_rep
	old = band(old, 0xf3) -- remove old value -- 11
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the replication.
--- @return replication as 2 bit integer.
function intHeader:getReplication()
	return band(rshift(self.ver_rep, 2), 0x03)
end

function intHeader:getReplicationString()
	return self:getReplication()
end

--- Set the copy.
--- @param int copy of the int header as 1 bit integer.
function intHeader:setCopy(int)
	int = int or 0
	int = band(lshift(int, 1), 0x02) -- fill to 8 bits
	--10
	old = self.ver_rep
	old = band(old, 0xfd) -- remove old value -- 01
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the copy.
--- @return copy as 1 bit integer.
function intHeader:getCopy()
	return band(rshift(self.ver_rep, 1), 0x01)
end

function intHeader:getCopyString()
	return self:getCopy()
end


--- Set the max hop count exceeded.
--- @param int max hop count exceeded of the int header as 1 bit integer.
function intHeader:setMaxHopCountExceeded(int)
	int = int or 0
	int = band(int, 0x01)

	old = self.ver_rep
	old = band(old, 0xfe) -- remove old value
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the max hop count exceeded.
--- @return max hop count exceeded as 1 bit integer.
function intHeader:getMaxHopCountExceeded()
	return band(self.ver_rep, 0x01)
end

function intHeader:getMaxHopCountExceededString()
	return self:getMaxHopCountExceeded()
end

--- Set the MTU exceeded.
--- @param int MTU exceeded of the int header as 1 bit integer.
function intHeader:setMTUExceeded(int)
	int = int or 0
	int = band(lshift(int, 7), 0x7f) -- fill to 8 bits

	old = self.byte2
	old = band(old, 0x80) -- remove old value

	self.byte2 = bor(old, int)
end

--- Retrieve the MTU exceeded.
--- @return max hop count exceeded as 1 bit integer.
function intHeader:getMTUExceeded()
	return band(rshift(self.byte2, 7), 0x01)
end

function intHeader:getMTUExceededString()
	return self:getMTUExceeded()
end

--- Set the Reserved Bits.
--- @param int Reserved bits of the int header as 10 bit integer.
function intHeader:setReserved1(int)
	int = int or 0

	-- 7bit in byte2 and 3 but in byte3

	-- right 3 bits
	right = band(int, 0x07)

	old = band(self.byte3, 0xf8)

	self.byte3 = band(right, old)
	
	-- left 7 bits
	left = band(rshift(int, 3), 0x7f) -- 7 bits

	old = self.byte2
	old = band(old, 0x80) -- remove old value

	self.byte2 = bor(old, left)
end

--- Retrieve the Reserved bits .
--- @return Reserved bits as 10 bit integer.
function intHeader:getReserved1()
	-- TODO
	return 0
end

function intHeader:getReserved1String()
	return self:getReserved1()
end

--- Set the Hop ML.
--- @param int Hop ML of the int header as 5 bit integer.
function intHeader:setHopML(int)
	int = int or 0
	int = bor(int, 0x1f)

	old = self.byte3
	old = band(old, 0xe0) -- remove old value

	self.byte3 = bor(old, int)
end

--- Retrieve the Hop ML.
--- @return Hop ML as 5 bit integer.
function intHeader:getHopML()
	return band(self.byte3, 0x7)
end

function intHeader:getHopMLString()
	return self:getHopML()
end

--- Set the Remaining Hop Count.
--- @param int Remaining Hop Count int header as 8 bit integer.
function intHeader:setRemainingHopCount(int)
	int = int or 0
	self.remainingHopCount = int
end

--- Retrieve the Hop ML.
--- @return Hop ML as 5 bit integer.
function intHeader:getRemainingHopCount()
	return self.remainingHopCount
end

function intHeader:getRemainingHopCountString()
	return self:getRemainingHopCount()
end

------------------------------------------------------
--- Next Field InstructionBitmap 16 bit
------------------------------------------------------

--- Set the instruction count.
--- @param int instruction count of the int header as 16 bit integer.
function intHeader:setInstructionBitmap(int)
	int = int or 0
	
	self.instructionBitmap = int
end

--- Retrieve the instruction count.
--- @return Instruction count as 5 bit integer.
function intHeader:getInstructionBitmap()
	return self.instructionBitmap
end

function intHeader:getInstructionBitmapString()
	return self:getInstructionBitmap()
end

------------------------------------------------------
--- Next Field Second Reserved 16 bit
------------------------------------------------------
--- Set the Reserved.
--- @param int reserved2 the int header as 16 bit integer.
function intHeader:setReserved(int)
	int = int or 0

	self.reserved2 = int
end

--- Retrieve the Reserved2.
--- @return Reserved2 as 16 bit integer.
function intHeader:getReserved()
	return self.reserved2
end

function intHeader:getReservedString()
	return self:getReserved()
end


------------------------------------------------


--- Set all members of the int header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: intXYZ
--- @param pre prefix for namedArgs. Default 'int'.
--- @code
--- fill() -- only default values
--- fill{ intXYZ=1 } -- all members are set to default values with the exception of intXYZ, ...
--- @endcode
function intHeader:fill(args, pre)
	args = args or {}
	pre = pre or "inbt"

	self:setType(args[pre .. "Type"] or 0)
	self:setReserved0(args[pre .. "Reserved0"] or 0)
	self:setLength(args[pre .. "Length"] or 3)
	self:setNextProtocol(args[pre .. "NextProtocol"] or 1)
	self:setVersion(args[pre .. "Version"])
	self:setReplication(args[pre .. "Replication"])
	self:setCopy(args[pre .. "Copy"])
	self:setMaxHopCountExceeded(args[pre .. "MaxHopCountExceeded"])
	self:setMTUExceeded(args[pre .. "MTUExceeded"])
	self:setReserved1(args[pre .. "Reserved1"])
	self:setHopML(args[pre .. "HopML"])
	self:setRemainingHopCount(args[pre .. "RemainingHopCount"])
	self:setInstructionBitmap(args[pre .. "InstructionBitmap"])
	self:setReserved(args[pre .. "Reserved"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'int'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see intHeader:fill
function intHeader:get(pre)
	pre = pre or "inbt"

	local args = {}
	args[pre .. "Type"] = self:getType()
	args[pre .. "Reserved0"] = self:getReserved0()
	args[pre .. "Length"] = self:getLength()
	args[pre .. "NextProtocol"] = self:getNextProtocol()
	args[pre .. "Version"] = self:getVersion()
	args[pre .. "Replication"] = self:getReplication()
	args[pre .. "Copy"] = self:getCopy()
	args[pre .. "MaxHopCountExceeded"] = self:getMaxHopCountExceeded()
	args[pre .. "MTUExceeded"] = self:getMTUExceeded()
	args[pre .. "Reserved1"] = self:getReserved1()
	args[pre .. "HopML"] = self:getHopML()
	args[pre .. "RemainingHopCount"] = self:getRemainingHopCount()
	args[pre .. "MaxHopCount"] = self:getMaxHopCount()
	args[pre .. "InstructionBitmap"] = self:getInstructionBitmap()
	args[pre .. "Reserved"] = self:getReserved()

	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function intHeader:getString()
	return "INT SHIM type " .. self:getTypeString()
		.. " r0 " .. self:getReserved0()
		.. " len " .. self:getLength()
		.. " next " .. self:getNextProtocol()
		.. "\nINT ver " .. self:getVersionString()
		.. " rep " .. self:getReplicationString()
		.. " C " .. self:getCopyString()
		.. " E " .. self:getMaxHopCountExceededString()
		.. " M " .. self:getMTUExceededString()
		.. " HopML " .. self:getHopMLString()
		.. " RHC " .. self:getRemainingHopCount()
		.. " IB " .. self:getInstructionBitmapString()
		.. " r2 " .. self:getReserved2()
end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function intHeader:resolveNextHeader()
	return self:getNextProtocol()
end	

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'int'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see intHeader:fill
function intHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	-- TODO nextHeader
	return namedArgs
end

function intHeader:getVariableLength()
	-- in 4 byte words, 3 for shim and int header
	return (self:getLength() - 3) * 4
end

------------------------------------------------------------------------
---- Meta
------------------------------------------------------------------------


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

mod.metatype = intHeader


return mod
