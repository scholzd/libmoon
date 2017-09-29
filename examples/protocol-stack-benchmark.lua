local lm	= require "libmoon"
local memory	= require "memory"
local device	= require "device"
local stats	= require "stats"
local log 	= require "log"
local ffi 	= require "ffi"

local C = ffi.C

ffi.cdef[[
	void wait_cycles(uint32_t wait);
]]

function configure(parser)
	parser:description("Generates TCP SYN flood from varying source IPs, supports both IPv4 and IPv6")
	parser:argument("mode", "Run loadgen or benchmark.")
	parser:argument("benchmark", "Benchmark to use")
	parser:argument("tx", "Device to send traffic to."):convert(tonumber)
	parser:argument("rx", "Device to receive traffic from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-b --bytes", "Depending on test: Bytes to increment or byte accessed"):default(100):convert(tonumber)
	parser:option("-l --length", "Packet length"):default(500):convert(tonumber)
	parser:option("-f --file", "Output file"):default('log.csv')
	parser:option("-c --cycles", "Wait cycles per packet"):default(0):convert(tonumber)
end

function master(args)
	local txDev = device.config{port = args.tx, txQueues = 1}
        local rxDev = device.config{port = args.rx, rxQueues = 1}
        device.waitForLinks()
	
	txDev:getTxQueue(0):setRate(args.rate)

        -- print statistics
        stats.startStatsTask{devices = {txDev, rxDev}, format='csv', file=args.file}

	if args.mode == 'loadgen' then
        	lm.startTask('dumpTask', rxDev:getRxQueue(0))
		lm.startTask('loadTask', txDev:getTxQueue(0), args.length)
	elseif args.mode == 'benchmark' then
        	lm.startTask(args.benchmark .. 'Bench', rxDev:getRxQueue(0), txDev:getTxQueue(0), args.bytes, args.length, args.cycles)
	else
		log:fatal('Unknown mode ' .. args.mode)
	end

        lm.waitForTasks()
end

function loadTask(queue, length)
	log:info('Starting load task')
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getRawPacket()
		for i = 0, length - 1 do
			pkt.payload.uint8[i] = 3
		end
		
		-- need to set proper ethertype
		buf:getEthPacket().eth:setType(0x0800)
	end)

	local bufs = mem:bufArray()
	while lm.running() do
		bufs:alloc(length)
		queue:send(bufs)
	end
end
local ctr  = 0
function dumpTask(queue)
	log:info('Starting dump task')
	local bufs = memory.bufArray()
	while lm.running() do
		local rx = queue:tryRecv(bufs, 100)
		--if rx > 0 and ctr < 100 then
		--	bufs[1]:dump()
		--	ctr = ctr + 1
		--end
		bufs:free(rx)
	end
end


function accessSequentialBytesBench(rxQueue, txQueue, bytes, length, cycles)
	log:info('Starting access sequential bytes benchmark')
	local rxBufs = memory.bufArray()
	
	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do 			
				C.wait_cycles(cycles)
				local rxPkt = rxBufs[i]:getRawPacket()
				for x = 0, bytes - 1 do
					rxPkt.payload.uint8[x] = rxPkt.payload.uint8[x] + 1
				end
			end
			txQueue:sendN(rxBufs, rx)
		end
	end
end

function accessSequentialBytesBackwardsBench(rxQueue, txQueue, bytes, length, cycles)
	log:info('Starting access sequential bytes backwards benchmark')
	local rxBufs = memory.bufArray()

	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do
				C.wait_cycles(cycles)
				local rxPkt = rxBufs[i]:getRawPacket()
				for x = bytes - 1, 0, -1 do
					rxPkt.payload.uint8[x] = rxPkt.payload.uint8[x] + 1
				end
			end
			txQueue:sendN(rxBufs, rx)
		end
	end
end

function accessSingleByteBench(rxQueue, txQueue, byte, length, cycles)
	log:info('Starting access single byte benchmark')
	local rxBufs = memory.bufArray()

	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do
				C.wait_cycles(cycles)
				local rxPkt = rxBufs[i]:getRawPacket()
				rxPkt.payload.uint8[byte] = rxPkt.payload.uint8[byte] + 1
			end
			txQueue:sendN(rxBufs, rx)
		end
	end
end

function accessMultipleBytesBench(rxQueue, txQueue, byte, length, cycles)
	log:info('Starting access single byte benchmark')
	local rxBufs = memory.bufArray()

	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do
				C.wait_cycles(cycles)
				local rxPkt = rxBufs[i]:getRawPacket()
				for x = 0, byte - 1 do
					rxPkt.payload.uint8[x * 64] = rxPkt.payload.uint8[x * 64] + 1
				end
			end
			txQueue:sendN(rxBufs, rx)
		end
	end
end

function copySequentialBytesBench(rxQueue, txQueue, bytes, length, cycles)
	log:info('Starting copy sequential bytes benchmark')
	local rxBufs = memory.bufArray()

	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getRawPacket()
		for i = 0, length - 1 do
			pkt.payload.uint8[i] = 9
		end
	end)
	local txBufs = mem:bufArray()

	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			txBufs:allocN(length, rx)
			for i = 1, rx do
				C.wait_cycles(cycles)
				local txPkt = txBufs[i]:getRawPacket()
				local rxPkt = rxBufs[i]:getRawPacket()
				ffi.copy(txPkt.payload, rxPkt.payload, bytes)
			end
			txQueue:sendN(txBufs, rx)
			rxBufs:freeAll()
		end
	end
end

function insertMemberBench(rxQueue, txQueue, bytes, length, cycles)
	log:info('Starting insert member benchmark')
	local rxBufs = memory.bufArray()

	while lm.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do
				local rxPkt = rxBufs[i]:getRawPacket()
				ffi.copy(txPkt.payload, rxPkt.payload, bytes)
			end
			rxQueue:sendN(rxBufs, rx)
		end
	end
end
