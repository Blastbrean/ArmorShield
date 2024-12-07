---@class digest
-- base digest class
local digest = {}

---virtual method "update"
---@param message_stream function
---@return digest
function digest:update(message_stream) end

---virtual method "finish"
---@return digest
function digest:finish() end

---virtual method "init"
---@return digest
function digest:init() end

---virtual method "as_bytes"
---@return number[]
function digest:as_bytes() end

---create new digest object
---@return digest
function digest.new()
	return setmetatable({}, { __index = digest })
end

-- return digest module
return digest
