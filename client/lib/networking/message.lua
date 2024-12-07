---@class message
---@field id packet_id
---@field data table
-- message communication type
local message = {}

---new message object
---@param id packet_id
---@param data table
---@return message
function message.new(id, data)
	-- create message object
	local self = setmetatable({}, { __index = message })
	self.id = id
	self.data = data

	-- return message object
	return self
end

-- return message module
return message
