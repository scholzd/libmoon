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
---- int header
---------------------------------------------------------------------------

mod.headerFormat = [[
	uint8_t		ver_rep;
	uint8_t		ins_cnt;
	uint8_t		MaxHopCount;
	uint8_t		TotalHopCount;
	uint16_t	InstructionBitmap;
	uint16_t	reserved;
	uint8_t	metadata[];
]]

--- Variable sized member
mod.headerVariableMember = "metadata"

--- Module for int_address struct
local intHeader = initHeader(mod.headerFormat)
intHeader.__index = intHeader
	
-- version | replication | copy | exceeded | reserved | inst cnt
-- XXYYCERR RRRZZZZZ

--- Set the version.
--- @param int version of the int header as 2 bit integer.
function intHeader:setVersion(int)
	int = int or 0
	int = band(lshift(int, 6), 0xc0) -- fill to 8 bits
	
	old = self.ver_rep
	old = band(old, 0x3f) -- remove old value
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the version.
--- @return version as 2 bit integer.
function intHeader:getVersion()
	return band(rshift(self.ver_rep, 6), 0x03)
end

function intHeader:getVersionString()
	return self:getVersion()
end

--- Set the replication.
--- @param int replication of the int header as 2 bit integer.
function intHeader:setReplication(int)
	int = int or 0
	int = band(lshift(int, 4), 0x30) -- fill to 8 bits
	
	old = self.ver_rep
	old = band(old, 0xcf) -- remove old value
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the replication.
--- @return replication as 2 bit integer.
function intHeader:getReplication()
	return band(rshift(self.ver_rep, 4), 0x03)
end

function intHeader:getReplicationString()
	return self:getReplication()
end

--- Set the copy.
--- @param int copy of the int header as 1 bit integer.
function intHeader:setCopy(int)
	int = int or 0
	int = band(lshift(int, 3), 0x08) -- fill to 8 bits
	
	old = self.ver_rep
	old = band(old, 0xf7) -- remove old value
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the copy.
--- @return copy as 1 bit integer.
function intHeader:getCopy()
	return band(rshift(self.ver_rep, 3), 0x01)
end

function intHeader:getCopyString()
	return self:getCopy()
end


--- Set the max hop count exceeded.
--- @param int max hop count exceeded of the int header as 1 bit integer.
function intHeader:setMaxHopCountExceeded(int)
	int = int or 0
	int = band(lshift(int, 2), 0x04) -- fill to 8 bits
	
	old = self.ver_rep
	old = band(old, 0xfb) -- remove old value
	
	self.ver_rep = bor(old, int)
end

--- Retrieve the max hop count exceeded.
--- @return max hop count exceeded as 1 bit integer.
function intHeader:getMaxHopCountExceeded()
	return band(rshift(self.ver_rep, 2), 0x01)
end

function intHeader:getMaxHopCountExceededString()
	return self:getMaxHopCountExceeded()
end

--- Set the instruction count.
--- @param int instruction count of the int header as 5 bit integer.
function intHeader:setInstructionCount(int)
	int = int or 0
	int = band(int, 0x1f) -- fill to 8 bits
	
	old = self.ins_cnt
	old = band(old, 0xe0) -- remove old value
	
	self.ins_cnt = bor(old, int)
end

--- Retrieve the instruction count.
--- @return Instruction count as 5 bit integer.
function intHeader:getInstructionCount()
	return band(self.ins_cnt, 0x1f)
end

function intHeader:getInstructionCountString()
	return self:getInstructionCount()
end

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

	self:setVersion(args[pre .. "Version"])
	self:setReplication(args[pre .. "Replication"])
	self:setCopy(args[pre .. "Copy"])
	self:setMaxHopCountExceeded(args[pre .. "MaxHopCountExceeded"])
	self:setInstructionCount(args[pre .. "InstructionCount"])
	self:setMaxHopCount(args[pre .. "MaxHopCount"])
	self:setTotalHopCount(args[pre .. "TotalHopCount"])
	self:setInstructionBitmap(args[pre .. "InstructionBitmap"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'int'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see intHeader:fill
function intHeader:get(pre)
	pre = pre or "inbt"

	local args = {}
	args[pre .. "Version"] = self:getVersion()
	args[pre .. "Replication"] = self:getReplication()
	args[pre .. "Copy"] = self:getCopy()
	args[pre .. "MaxHopCountExceeded"] = self:getMaxHopCountExceeded()
	args[pre .. "InstructionCount"] = self:getInstructionCount()
	args[pre .. "MaxHopCount"] = self:getMaxHopCount()
	args[pre .. "TotalHopCount"] = self:getTotalHopCount()
	args[pre .. "InstructionBitmap"] = self:getInstructionBitmap()

	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function intHeader:getString()
	return "int ver " .. self:getVersionString()
		.. " rep " .. self:getReplicationString()
		.. " C " .. self:getCopyString()
		.. " MHCE " .. self:getMaxHopCountExceededString()
		.. " IC " .. self:getInstructionCountString()
		.. " MHC " .. self:getMaxHopCountString()
		.. " THC " .. self:getTotalHopCountString()
		.. " IB " .. self:getInstructionBitmapString()
end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function intHeader:resolveNextHeader()
	return nil
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
	return namedArgs
end

function intHeader:getVariableLength()
	return (self:getInstructionCount() * self:getTotalHopCount()) * 4
end

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

mod.metatype = intHeader


return mod
