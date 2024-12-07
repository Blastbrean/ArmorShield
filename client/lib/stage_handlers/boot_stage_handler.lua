---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@class boot_stage_handler: stage_handler
---@field timestamp number
---@field subscription_id string
-- handle the bootstrapping stage
local boot_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.stage_handlers.handshake_stage_handler
local handshake_stage_handler = require("lib.stage_handlers.handshake_stage_handler")

---@module lib.networking.deserializer
local deserializer = require("lib.networking.deserializer")

---@module lib.prng
local prng = require("lib.prng")

---@module lib.logger
local logger = require("lib.logger")

---@module lib.keys.curve25519
local curve25519 = require("lib.keys.curve25519")

---@module lib.uuid
local uuid = require("lib.uuid")

---@module lib.utility
local utility = require("lib.utility")

---@compile_time: script's curve point
local DB_CURVE_POINT = {}

---boot stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function boot_stage_handler:handle_packet(conn_data, pk)
	local boot_msg = deserializer.unmarshal_one(pk.Msg)

	self.subscription_id = boot_msg.SubId
	self.timestamp = boot_msg.BaseTimestamp

	logger.warn("acknowledged at %i", self.timestamp)
	logger.warn("booted up as subscription %s", uuid.hex_string(self.subscription_id))

	local private_key = utility.shift(prng.get_byte_table(32), -1)
	local public_key = utility.shift(curve25519.X25519(private_key, utility.shift(DB_CURVE_POINT, -1)), 1)

	conn_data.stage_handler = handshake_stage_handler.new(private_key, self)
	conn_data:set_client_stage(1)
	conn_data:send_message(1, {
		["ClientPublicKey"] = public_key,
	})

	logger.warn("sws tunnel being initialized")
end

---boot stage handler's packet id
---@return packet_id
function boot_stage_handler:handle_packet_id()
	return 0
end

---boot stage handler's client stage
---@return client_stage
function boot_stage_handler:handle_client_stage()
	return 0
end

---new boot stage handler object
---@return boot_stage_handler
function boot_stage_handler.new()
	return setmetatable(stage_handler.new(), { __index = boot_stage_handler })
end

-- return boot stage handler module
return boot_stage_handler
