local lm     = require "libmoon"
local log    = require "log"
local memory = require "memory"
local packet    = require "packet"


local function compareTables(t1, t2) 
	if #t1 ~= #t2 then
		return false
	else
		for k, v in pairs(t1) do
			if t2[k] ~= v then
				return false
			end
		end
	end
	return true
end

function master(args,...)
	print(white('Test adjustStack'))
	local stack = 'Test'
	packet['get' .. stack .. 'Packet'] = createStack('eth', { 'ip4', length=12 }, { 'tcp', length=20 }, 'vxlan' )
	packet['get' .. stack .. 'PacketUnknown'] = createStack('eth', 'ip4', 'tcp', 'vxlan' )
	local initial
	local mempool = memory.createMemPool(function(buf)
		local pkt = packet['get' .. stack .. 'Packet'](buf)
		pkt:fill()
		initial = pkt:get()
	end)
	local bufs = mempool:bufArray(1)
	bufs:alloc(100)
	for _, buf in ipairs(bufs) do
		local pkt = packet['get' .. stack .. 'PacketUnknown'](buf)
		local unknown = pkt:get()
		pkt = pkt:adjustStack(buf)
		local resolved = pkt:get()

		local notMismatch = compareTables(initial, unknown)
		local match = compareTables(initial, resolved)
		if notMismatch then
			log:error('Although the packet should be unknown now, it does match with the initial packet')
		end
		if not match then
			log:error('Packets did not match after stack adjustment')
		end
		if not notMismatch and match then
			print(green('OK: could adjust two length members'))
		end
	end
end

