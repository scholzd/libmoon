local mg	= require "moongen"
local memory	= require "memory"
local device	= require "device"
local stats	= require "stats"
local log 	= require "log"
local ffi 	= require "ffi"

function configure(parser)
	parser:description("Generates TCP SYN flood from varying source IPs, supports both IPv4 and IPv6")
	parser:argument("genDev", "Device to gen/rec traffic from."):convert(tonumber)
	parser:argument("benchDev", "Device to benchmark on."):convert(tonumber)
	parser:argument("benchmark", "Benchmark to use"):default(0):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-b --bytes", "Bytes to increment"):default(100):convert(tonumber)
	parser:option("-l --length", "Packet length"):default(500):convert(tonumber)
end

function master(args)
	local genDev = device.config{port = args.genDev, rxQueues = 1, txQueues = 1}
        local benchDev = device.config{port = args.benchDev, rxQueues = 1, txQueues = 1}
        device.waitForLinks()
		
	genDev:getTxQueue(0):setRate(args.rate)

        -- print statistics
        stats.startStatsTask{devices = {genDev, benchDev}}

        mg.startTask('dumpTask', genDev:getRxQueue(0))
        mg.startTask('loadTask', genDev:getTxQueue(0), args.length)

	if args.benchmark == 0 then
        	mg.startTask('accessSequentialBytesBench', benchDev:getRxQueue(0), benchDev:getTxQueue(0), args.bytes, args.length)
        elseif args.benchmark == 1 then
		mg.startTask('copySequentialBytesBench', benchDev:getRxQueue(0), benchDev:getTxQueue(0), args.bytes, args.length)
	end

        mg.waitForTasks()
end

function loadTask(queue, length)
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getRawPacket()
		for i = 0, length - 1 do
			pkt.payload.uint8[i] = 3
		end
		
		-- need to set proper ethertype
		buf:getEthPacket().eth:setType(0x0800)
	end)

	local bufs = mem:bufArray()
	while mg.running() do
		bufs:alloc(length)
		queue:send(bufs)
	end
end
local ctr  = 0
function dumpTask(queue)
	local bufs = memory.bufArray()
	while mg.running() do
		local rx = queue:tryRecv(bufs, 100)
		if rx > 0 and ctr < 100 then
			bufs[1]:dump()
			ctr = ctr + 1
		end
		bufs:free(rx)
	end
end


function accessSequentialBytesBench(rxQueue, txQueue, bytes, length)
	local rxBufs = memory.bufArray()
	
	while mg.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			for i = 1, rx do 			
				local rxPkt = rxBufs[i]:getRawPacket()
				for x = 0, bytes - 1 do
					rxPkt.payload.uint8[x] = rxPkt.payload.uint8[x] + 1
				end
			end
			txQueue:sendN(rxBufs, rx)
		end
	end
end

function copySequentialBytesBench(rxQueue, txQueue, bytes, length)
	local rxBufs = memory.bufArray()

	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getRawPacket()
		for i = 0, length - 1 do
			pkt.payload.uint8[i] = 9
		end
	end)
	local txBufs = mem:bufArray()

	while mg.running() do
		local rx = rxQueue:recv(rxBufs)
		if rx > 0 then
			txBufs:allocN(length, rx)
			for i = 1, rx do
				local txPkt = txBufs[i]:getRawPacket()
				local rxPkt = rxBufs[i]:getRawPacket()
				ffi.copy(txPkt.payload, rxPkt.payload, bytes)
			end
			txQueue:sendN(txBufs, rx)
			rxBufs:freeAll()
		end
	end
end

function insertMemberBench(rxQueue, txQueue, bytes, length)
	local rxBufs = memory.bufArray()

	while mg.running() do
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
