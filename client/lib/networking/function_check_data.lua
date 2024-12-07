---@class function_check_data
local function_check_data = {}

---function check data str
---@param str string
---@return function_check_data
function function_check_data.str(str)
	return function_check_data.new(str, nil, nil, nil, nil, nil)
end

---function check data byte
---@param byte number
---@return function_check_data
function function_check_data.byte(byte)
	return function_check_data.new(nil, nil, nil, nil, nil, byte)
end

---function check data boolean
---@param bool boolean
---@return function_check_data
function function_check_data.bool(bool)
	return function_check_data.new(nil, nil, bool, nil, nil)
end

---function check data string array
---@param str_array string[]
---@return function_check_data
function function_check_data.str_array(str_array)
	return function_check_data.new(nil, str_array, nil, nil, nil, nil)
end

---function check data get info
---@param get_info table
---@return function_check_data
function function_check_data.get_info(get_info)
	return function_check_data.new(nil, nil, nil, get_info, nil, nil)
end

---function check data info
---@param info table
---@return function_check_data
function function_check_data.info(info)
	return function_check_data.new(nil, nil, nil, nil, info, nil)
end

---new function check data object
---@param str string?
---@param string_array string[]?
---@param bool boolean?
---@param get_info table?
---@param info table?
---@return packet
function function_check_data.new(str, string_array, bool, get_info, info, byte)
	-- create new function check data object
	local self = setmetatable({}, { __index = function_check_data })
	self["String"] = str
	self["StringArray"] = string_array
	self["Boolean"] = bool
	self["GetInfo"] = get_info
	self["Info"] = info
	self["Byte"] = byte

	-- return new function check data object
	return self
end

-- return function check data module
return function_check_data
