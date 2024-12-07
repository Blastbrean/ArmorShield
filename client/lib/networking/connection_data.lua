---@alias client_stage
---| '0' During or after bootstrapping has been finished
---| '1' Waiting for the handshake process to be finished
---| '2' Waiting for the establishment process to be finished
---| '3' Waiting for the identification process to be finished
---| '4' During or after the client loading process has been finished

---@class connection_data
---@field data_listeners function[]
---@field key_update_listeners function[]
---@field packets packet[]
---@field garbage any[]
---@field heartbeat boolean[]
---@field messages message[]
---@field closing boolean
---@field closed boolean
---@field handshake_stage_handler handshake_stage_handler
---@field current_stage client_stage
---@field stage_handler stage_handler
---@field lycoris_init table|nil
---@field script_task thread|nil
-- this class specifies the structure for connection data
local connection_data = {}

---@module lib.networking.deserializer
local deserializer = require("lib.networking.deserializer")

---@module lib.logger
local logger = require("lib.logger")

---@module lib.networking.message
local message = require("lib.networking.message")

---@module lib.networking.packet
local packet = require("lib.networking.packet")

---@module lib.profiler
local profiler = require("lib.profiler")

---@module lib.utility
local utility = require("lib.utility")

-- cached functions
local string_format = string.format
local lua_pcall = pcall
local base64_encode = base64.encode

---disconnect
---@param reason string
function connection_data:disconnect(reason, ...)
	if self.closing then
		return
	end

	local msg = string_format(reason, ...)

	logger.warn("client disconnecting (%s)", msg)

	self.closing = true
end

---handle drop
---@param msg number[]
function connection_data:handle_drop(msg)
	if self.closing then
		return
	end

	local drop_msg = deserializer.unmarshal_one(msg)
	local drop_reason = drop_msg["Reason"]

	logger.warn("server dropping client (%s)", drop_reason)

	self.closing = true
end

---set client stage
---@param stage client_stage
function connection_data:set_client_stage(stage)
	self.current_stage = stage
	logger.warn("set client stage (%i)", stage)
end

---send packet to packet queue
---@param id packet_id
---@param msg string
function connection_data:send_packet(id, msg)
	self.packets[#self.packets + 1] = packet.new(id, msg)
	logger.warn("queue pushed packet (%i)", id)
end

---send message to message queue
---@param id packet_id
---@param data table
function connection_data:send_message(id, data)
	self.messages[#self.messages + 1] = message.new(id, data)
	logger.warn("queue pushed message (%i)", id)
end

---handle packet
---@param data number[]
function connection_data:handle_packet(data)
	logger.warn("deserializing packet (%i)", #data)

	local success, pk = lua_pcall(deserializer.unmarshal_one, data)

	if not success then
		logger.warn("raw packet data: %s", base64_encode(utility.to_string(data)))
		return self:disconnect("packet deserialization error")
	end

	if typeof(pk) ~= "table" then
		logger.warn("raw packet data: %s", base64_encode(utility.to_string(data)))
		return self:disconnect("packet deserialize fail 1")
	end

	if pk.Id == nil or pk.Msg == nil then
		logger.warn("raw packet data: %s", base64_encode(utility.to_string(data)))
		return self:disconnect("packet deserialize fail 2")
	end

	profiler.run_function(
		string_format("ArmorShield_Packet_Marker_%i", pk.Id),
		logger.warn,
		"handling packet (%i)",
		pk.Id
	)

	if pk.Id == 5 then
		return self:handle_drop(pk.Msg)
	end

	if pk.Id == 6 then
		return self.key_update_stage_handler and self.key_update_stage_handler:handle_packet(self, pk)
	end

	if pk.Id == 7 then
		return self.handshake_stage_handler and self.handshake_stage_handler:send_message(self, pk.Id, {})
	end

	if pk.Id ~= self.stage_handler:handle_packet_id() then
		return self:disconnect("packet mismatch (%i vs. %i)", pk.Id, self.stage_handler:handle_packet_id())
	end

	if self.current_stage ~= self.stage_handler:handle_client_stage() then
		return self:disconnect(
			"stage mismatch (%i vs. %i)",
			self.current_stage,
			self.stage_handler:handle_client_stage()
		)
	end

	if self.security then
		self.security_tick = self.security_tick + 1

		logger.warn("security tick (%i)", self.security_tick)

		profiler.run_function("ArmorShield_SecurityTick", self.security.tick, self.security, self)
	end

	self.stage_handler:handle_packet(self, pk)

	logger.warn("finished handling packet (%i)", pk.Id)
end

---new connection data object
---@param default_stage client_stage
---@param default_stage_handler stage_handler
---@return connection_data
function connection_data.new(default_stage, default_stage_handler)
	-- create connection object
	local self = setmetatable({}, { __index = connection_data })
	self.packets = {}
	self.messages = {}
	self.garbage = {}
	self.heartbeat = {}
	self.data_listeners = {}
	self.key_update_listeners = {}
	self.closing = false
	self.closed = false
	self.current_stage = default_stage
	self.stage_handler = default_stage_handler
	self.handshake_stage_handler = nil
	self.lycoris_init = nil
	self.script_task = nil

	-- return connection object
	return self
end

-- return connection data module
return connection_data
