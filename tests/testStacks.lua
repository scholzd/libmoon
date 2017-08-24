local lm     = require "libmoon"
local log    = require "log"
local memory = require "memory"
require "utils"


function master(args,...)
	print(white('Test creating stacks and matchesStack'))
	stacks = { 
		'Raw',
		'Eth',
		'EthVlan',
		'Arp',
		'IP4',
		'IP6',
		'Icmp4',
		'Icmp6',
		'Udp4',
		'Udp6',
		'Tcp4',
		'Tcp6',
		'UdpPtp',
		'VxlanEthernet',
		'Esp',
		'AH',
		'Dns',
		'SFlow',
		'Ipfix',
		'Lacp',
	}
	for _, stack in ipairs(stacks) do
		local mempool = memory.createMemPool(function(buf)
			buf['get' .. stack .. 'Packet'](buf):fill()
		end)
		local bufs = mempool:bufArray(1)
		bufs:alloc(100)
		local ok = true
		for i, buf in ipairs(bufs) do
			local pkt = buf['get' .. stack .. 'Packet'](buf)
			if not (stack == 'Raw') then
				local before = pkt:matchesStack()
				pkt.eth:setType(0)
				local after = pkt:matchesStack()
				if not before then
					log:error('Stack does not match before ' .. stack)
					ok = false
				end
				if after and not (stack == 'Eth' or stack == 'EthVlan')then
					log:error('Stack does match after ' .. stack)
					ok = false
				end
			end
			print(green('OK: ' .. stack))
		end
	end
end

