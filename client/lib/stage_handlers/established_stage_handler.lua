---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@class established_stage_handler: stage_handler
---@field handshake_stage_handler handshake_stage_handler
-- finish establishing the SWS tunnel
local established_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.stage_handlers.analytics_stage_handler
local analytics_stage_handler = require("lib.stage_handlers.analytics_stage_handler")

---@module lib.uuid
local uuid = require("lib.uuid")

---@module lib.logger
local logger = require("lib.logger")

---@module lib.internal.analytics
local analytics = require("lib.internal.analytics")

---established stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function established_stage_handler:handle_packet(conn_data, pk)
	local establish_msg = self.handshake_stage_handler:unmarshal_one(conn_data, pk.Msg)
	if not establish_msg then
		return
	end

	if
		uuid.hex_string(establish_msg["SubId"])
		~= uuid.hex_string(self.handshake_stage_handler.boot_stage_handler.subscription_id)
	then
		return conn_data:disconnect("subscription mismatch")
	end

	if establish_msg["BaseTimestamp"] ~= self.handshake_stage_handler.boot_stage_handler.timestamp then
		return conn_data:disconnect("timestamp mismatch")
	end

	conn_data.stage_handler = analytics_stage_handler.new(self.handshake_stage_handler)
	conn_data:set_client_stage(3)

	logger.warn("calculating analytics information")

	self.handshake_stage_handler:send_message(conn_data, 3, {
		["KeyInfo"] = analytics.get_key_info(),
		["SubInfo"] = analytics.get_sub_info(),
	})

	logger.warn("sws tunnel established")
end

---established stage handler's packet id
---@return packet_id
function established_stage_handler:handle_packet_id()
	return 2
end

---established stage handler's client stage
---@return client_stage
function established_stage_handler:handle_client_stage()
	return 2
end

---new established stage handler object
---@param handshake_stage_handler handshake_stage_handler
---@return established_stage_handler
function established_stage_handler.new(handshake_stage_handler)
	-- create established data stage handler object
	local self = setmetatable(stage_handler.new(), { __index = established_stage_handler })
	self.handshake_stage_handler = handshake_stage_handler

	-- return established data stage handler object
	return self
end

-- return established stage handler module
return established_stage_handler
