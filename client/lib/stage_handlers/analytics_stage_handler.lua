---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@module lib.logger
local logger = require("lib.logger")

---@class analytics_stage_handler: stage_handler
---@field handshake_stage_handler handshake_stage_handler
-- finish establishing the SWS tunnel
local analytics_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.stage_handlers.load_stage_handler
local load_stage_handler = require("lib.stage_handlers.load_stage_handler")

---analytics stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function analytics_stage_handler:handle_packet(conn_data, pk)
	logger.warn("analytics gate (%i, %i)", pk.Id, conn_data.current_stage)

	local analytics_msg = self.handshake_stage_handler:unmarshal_one(conn_data, pk.Msg)
	if not analytics_msg then
		return
	end

	logger.warn("setting up loading stage")

	conn_data.stage_handler = load_stage_handler.new(self)
	conn_data:set_client_stage(4)

	logger.warn("requesting loading for universe id %i", game.GameId)

	self.current_role = analytics_msg["CurrentRole"]
	self.handshake_stage_handler:send_message(conn_data, 4, {
		["GameId"] = game.GameId,
	})

	logger.warn("finished request - waiting for load")
end

---analytics stage handler's packet id
---@return packet_id
function analytics_stage_handler:handle_packet_id()
	return 3
end

---analytics stage handler's client stage
---@return client_stage
function analytics_stage_handler:handle_client_stage()
	return 3
end

---new analytics stage handler object
---@param handshake_stage_handler handshake_stage_handler
---@return analytics_stage_handler
function analytics_stage_handler.new(handshake_stage_handler)
	-- create analytics data stage handler object
	local self = setmetatable(stage_handler.new(), { __index = analytics_stage_handler })
	self.handshake_stage_handler = handshake_stage_handler

	-- return analytics data stage handler object
	return self
end

-- return analytics stage handler module
return analytics_stage_handler
