--- A simple UDP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local packet = require 'packet'
require "utils"
local time = time

-- set addresses here
local DST_MAC       = nil -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local PKT_LEN       = 60
local SRC_IP        = "10.0.0.10"
local DST_IP        = "10.1.0.10"
local SRC_PORT_BASE = 1234 -- actual port will be SRC_PORT_BASE * random(NUM_FLOWS)
local DST_PORT      = 1234
local NUM_FLOWS     = 1000
-- used as source IP to resolve GW_IP to DST_MAC
-- also respond to ARP queries on this IP
local ARP_IP	= SRC_IP
-- used to resolve DST_MAC
local GW_IP		= DST_IP


-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	parser:description("Edit the source to modify constants like IPs and ports.")
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("-t --threads", "Number of threads per device."):args(1):convert(tonumber):default(1)
	parser:option("-r --rate", "Transmit rate in Mbit/s per device."):args(1)
	return parser:parse()
end

function master(args,...)
	log:info("Check out MoonGen (built on lm) if you are looking for a fully featured packet generator")
	log:info("https://github.com/emmericp/MoonGen")

	-- configure devices and queues
	local arpQueues = {}
	for i, dev in ipairs(args.dev) do
		-- arp needs extra queues
		local dev = device.config{
			port = dev,
			txQueues = args.threads + (args.arp and 1 or 0),
			rxQueues = args.arp and 2 or 1
		}
		args.dev[i] = dev
	end
	device.waitForLinks()

	-- print statistics

	-- configure tx rates and start transmit slaves
	for i, dev in ipairs(args.dev) do
		for i = 1, args.threads do
			local queue = dev:getTxQueue(i - 1)
			if args.rate then
				queue:setRate(args.rate / args.threads)
			end
			lm.startTask("txSlave", queue, DST_MAC)
		end
	end
	local start = time()
	local cur = time()
	while cur - start < 5 do
		cur = time()
	end
	lm.stop()
	lm.waitForTasks()
end

function txSlave(queue, dstMac)
	local test = createStack('eth', {'ip4', length=12}, {'tcp', length=20}, 'vxlan')--createStack({'ip4', length=12}, {'ip4', name='inner', length=20})
	local test2 =createStack('eth', 'ip4', 'tcp', 'vxlan') --createStack({'ip4'}, {'ip4', name='inner'})
	local test3 = createStack('eth', 'ip4', {'tcp', forceLength = 1}, 'vxlan')
	-- memory pool with default values for all packets, this is our archetype
	local mempool = memory.createMemPool(function(buf)
		test(buf):fill{
			-- fields not explicitly set here are initialized to reasonable defaults
			ethSrc = queue, -- MAC of the tx device
			ethDst = dstMac,
			ip4Src = SRC_IP,
			ip4Dst = DST_IP,
			--ip4HeaderLength = ,
			--innerHeaderLength = 5,
			udpSrc = SRC_PORT,
			udpDst = DST_PORT,
			pktLength = PKT_LEN
		}
	end)
	-- a bufArray is just a list of buffers from a mempool that is processed as a single batch
	local bufs = mempool:bufArray()
	local ctr = stats:newManualTxCounter(queue.dev, 'plain')
	local rx
	local num
	local sum = 0
	local phase = 0
	while lm.running() do -- check if Ctrl+c was pressed
		bufs:alloc(PKT_LEN)
		num = 0
		for i, buf in ipairs(bufs) do
			local pkt = test(buf)
			--pkt:dump()
			pkt = pkt:adjustStack(buf)
			sum = sum + pkt.tcp:getSrc()
			
			--pkt:dump()
			--lm.stop()
			num = i
			--return
		end
		ctr:update(num, num * PKT_LEN)
	end
	print(sum)
	ctr:finalize()
end

