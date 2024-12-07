---@class stage_handler
-- base stage handler class
local stage_handler = {}

---virtual method "handle_packet" - handle packet
---@param conn_data connection_data
---@param packet any
function stage_handler:handle_packet(conn_data, packet) end

---virtual method "handle_packet_id" - specify what packet this handler is for
---@return packet_id
function stage_handler:handle_packet_id() end

---virtual method "handle_client_stage" - specify what client stage this handler is for
---@return client_stage
function stage_handler:handle_client_stage() end

---create new stage handler object
---@return stage_handler
function stage_handler.new()
	return setmetatable({}, { __index = stage_handler })
end

-- return stage handler module
return stage_handler
