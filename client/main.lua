-- cached functions
local ws_connect, lua_pcall, task_spawn, task_wait, coroutine_status, load_string =
	WebSocket.connect, pcall, task.spawn, task.wait, coroutine.status, loadstring

-- lph macros
if not LPH_OBFUSCATED then
	load_string([[
		function LPH_NO_VIRTUALIZE(...) return ... end
	]])()
end

---@module lib.logger
local logger = require("lib.logger")

---@module lib.networking.connection_data
local connection_data = require("lib.networking.connection_data")

---@module lib.stage_handlers.boot_stage_handler
local boot_stage_handler = require("lib.stage_handlers.boot_stage_handler")

---@module lib.networking.serializer
local serializer = require("lib.networking.serializer")

---@module lib.networking.packet
local packet = require("lib.networking.packet")

---@module lib.utility
local utility = require("lib.utility")

---@module lib.profiler
local profiler = require("lib.profiler")

-- websocket connection
local ws_client = nil

-- max connection atempts
local MAX_CONNECION_ATEMPTS = 3
local REPEAT_ATTEMPT_COOLDOWN_SECS = 5

-- attempt connection (3 tries at 5s repeats...)
for attempt = 1, MAX_CONNECION_ATEMPTS do
	logger.warn("attempting to connect to server (current: %i, max: %i)", attempt, MAX_CONNECION_ATEMPTS)

	local success, result = nil, nil

	if not LPH_OBFUSCATED then
		success, result = lua_pcall(ws_connect, "ws://armorshield.com:8090/subscribe")
	else
		success, result = lua_pcall(ws_connect, "wss://armorshield.online/subscribe")
	end

	if success and result then
		ws_client = result
		break
	end

	if attempt == MAX_CONNECION_ATEMPTS then
		return logger.warn("failed to connect to server (%s)", result)
	end

	logger.warn("retrying connection to server (%s) (retrying in %is)", result, REPEAT_ATTEMPT_COOLDOWN_SECS)

	task_wait(REPEAT_ATTEMPT_COOLDOWN_SECS)
end

-- cached websocket functions
local on_message, on_close, send_msg, close_client =
	ws_client.OnMessage, ws_client.OnClose, ws_client.Send, ws_client.Close

-- connection data
local conn_data = connection_data.new(0, boot_stage_handler.new())

-- fetch executor name
local executor_name = getexecutorname and table.pack(getexecutorname()) or nil

-- check if it's a table
if typeof(executor_name) == "table" then
	executor_name = table.concat(executor_name, " ")
else
	executor_name = tostring(executor_name)
end

-- force use test key if in test mode
if not LPH_OBFUSCATED then
	script_key = "fn1v5trmdf10b9h"
end

-- boot client
conn_data:send_message(0, {
	["KeyId"] = script_key or "N/A",
	["ExploitName"] = executor_name,
})

---write packet
---@param packet_object packet
local function write_packet(packet_object)
	local serialized_packet_object = serializer.marshal(packet_object)
	local hex_encoded = serialized_packet_object:gsub(".", function(char)
		return ("%02x"):format(char:byte())
	end)

	logger.warn("packet write (%i, %i, %i)", packet_object.Id, #packet_object.Msg, #hex_encoded)

	return send_msg(ws_client, hex_encoded)
end

---write message
---@param message message
local function write_message(message)
	local packet_object = packet.new(message.id, serializer.marshal(message.data))
	return write_packet(packet_object)
end

---handle messages
local function handle_messages()
	local messages = conn_data.messages
	local messages_size = #messages

	for _, message in next, messages do
		write_message(message)
	end

	if messages_size > 0 then
		logger.warn("handle message queue (%i)", messages_size)
	end

	conn_data.messages = {}

	return messages_size
end

---handle packets
local function handle_packets()
	local packets = conn_data.packets
	local packets_size = #packets

	for _, packet_object in next, packets do
		write_packet(packet_object)
	end

	if packets_size > 0 then
		logger.warn("handle packet queue (%i)", packets_size)
	end

	conn_data.packets = {}

	return packets_size
end

---handle close
local function handle_close()
	if not conn_data.closing then
		return
	end

	logger.warn("client closing (requested close)")

	close_client(ws_client)

	error("connection closed (requested close)")
end

---handler loop
local function handler_loop()
	handle_messages()
	handle_packets()
	handle_close()
end

---handle data as packets
---@param data string
on_message:Connect(function(data)
	task_spawn(profiler.wrap_function("ArmorShield_OnMessage", function()
		local handle_success, handle_error = lua_pcall(conn_data.handle_packet, conn_data, utility.to_byte_array(data))

		if not handle_success then
			logger.warn("error while handling packet (%s)", handle_error)
		end
	end))
end)

---handle close and clean-up
on_close:Connect(function()
	task_spawn(function()
		conn_data.closed = true
	end)
end)

-- log connection start & handler creation
logger.warn("connection started")

-- handler loop
while task_wait() do
	local handle_success, handle_error = lua_pcall(profiler.wrap_function("ArmorShield_HandlerLoop", handler_loop))

	if handle_success then
		continue
	end

	if conn_data.script_function then
		break
	end

	logger.warn("handler loop return - loader stopping (%s)", handle_error)
	break
end

-- close client
close_client(ws_client)

-- running
logger.warn("script running (connection closed for stability)")

-- run script
conn_data.script_function()