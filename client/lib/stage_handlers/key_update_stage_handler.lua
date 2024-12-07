---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@class key_update_stage_handler: stage_handler
---@field handshake_stage_handler handshake_stage_handler
-- handle a key update
local key_update_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.logger
local logger = require("lib.logger")

---key update stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function key_update_stage_handler:handle_packet(conn_data, pk)
	local key_update_msg = self.handshake_stage_handler:unmarshal_one(conn_data, pk.Msg)
	if not key_update_msg then
		return
	end

	conn_data.lycoris_init.current_role = key_update_msg["Role"]

	logger.warn("key update (%s) to (%i) listeners", key_update_msg["Role"], #conn_data.key_update_listeners)

	for _, listener in next, conn_data.key_update_listeners do
		listener(key_update_msg)
	end
end

---new key update stage handler object
---@param handshake_stage_handler handshake_stage_handler
---@return key_update_stage_handler
function key_update_stage_handler.new(handshake_stage_handler)
	-- create new key update stage handler object
	local self = setmetatable(stage_handler.new(), { __index = key_update_stage_handler })
	self.handshake_stage_handler = handshake_stage_handler

	-- return new key update stage handler object
	return self
end

-- return key update stage handler module
return key_update_stage_handler
