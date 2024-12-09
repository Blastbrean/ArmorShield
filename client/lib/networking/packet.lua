---@alias packet_id
---| '0' Bootstrap the entire connection
---| '1' Handshake between both parties to establish SWS
---| '2' Identify the client
---| '3' Send the script to the client
---| '4' Connection is closing and we are being sent a reason
---| '5' Key data is being updated

---@class packet
---@field Id packet_id
---@field Msg string
local packet = {}

---new packet object
---@param id packet_id
---@param msg string
---@return packet
function packet.new(id, msg)
	-- create new packet object
	local self = setmetatable({}, { __index = packet })
	self["Id"] = id
	self["Msg"] = msg

	-- return new packet object
	return self
end

-- return packet module
return packet
