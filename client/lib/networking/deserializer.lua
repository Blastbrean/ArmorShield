-- deserializer module
local deserializer = {}

-- cached functions
local lua_error = error
local lua_typeof = typeof

---@module lib.networking.deserializer_stream
local deserializer_stream = require("lib.networking.deserializer_stream")

-- deserialization data map
local byte_to_data_map = {
	[0xc0] = nil,
	[0xc2] = false,
	[0xc3] = true,
	[0xc4] = deserializer_stream.byte,
	[0xc5] = deserializer_stream.short,
	[0xc6] = deserializer_stream.int,
	[0xca] = deserializer_stream.float,
	[0xcb] = deserializer_stream.double,
	[0xcc] = deserializer_stream.byte,
	[0xcd] = deserializer_stream.unsigned_short,
	[0xce] = deserializer_stream.unsigned_int,
	[0xcf] = deserializer_stream.unsigned_long,
	[0xd0] = deserializer_stream.byte,
	[0xd1] = deserializer_stream.short,
	[0xd2] = deserializer_stream.int,
	[0xd3] = deserializer_stream.long,
	[0xd9] = deserializer_stream.byte,
	[0xda] = deserializer_stream.unsigned_short,
	[0xdb] = deserializer_stream.unsigned_int,
	[0xdc] = deserializer_stream.unsigned_short,
	[0xdd] = deserializer_stream.unsigned_int,
	[0xde] = deserializer_stream.unsigned_short,
	[0xdf] = deserializer_stream.unsigned_int,
}

---decode array with a specific length and recursively read
---@param stream deserializer_stream
---@param length number
---@return table
local function decode_array(stream, length)
	local elements = {}

	for i = 1, length do
		elements[i] = deserializer.at(stream)
	end

	return elements
end

---decode map with a specific length and recursively read
---@param stream deserializer_stream
---@param length number
---@return table, number
local function decode_map(stream, length)
	local elements = {}

	for _ = 1, length do
		elements[deserializer.at(stream)] = deserializer.at(stream)
	end

	return elements
end

---deserialize the data at a specific position
---@param stream deserializer_stream
---@return any
function deserializer.at(stream)
	---@type number
	local byte = stream:byte()

	---@type number|boolean|function
	local byte_data = byte_to_data_map[byte] or function()
		lua_error("unhandled byte data: " .. byte)
	end

	if byte == 0xde or byte == 0xdf then
		return decode_map(stream, byte_data(stream))
	end

	if byte >= 0x80 and byte <= 0x8f then
		return decode_map(stream, byte - 0x80)
	end

	if byte >= 0x90 and byte <= 0x9f then
		return decode_array(stream, byte - 0x90)
	end

	if byte == 0xdc or byte == 0xdd then
		return decode_array(stream, byte_data(stream))
	end

	if byte == 0xc4 or byte == 0xc5 or byte == 0xc6 then
		return stream:le_read_bytes(byte_data(stream))
	end

	if byte == 0xd9 or byte == 0xda or byte == 0xdb then
		return stream:string(byte_data(stream))
	end

	if byte >= 0xa0 and byte <= 0xbf then
		return stream:string(byte - 0xa0)
	end

	if byte == 0xc0 or byte == 0xc1 or byte == 0xc2 then
		return byte_to_data_map[byte]
	end

	if byte >= 0x00 and byte <= 0x7f then
		return byte
	end

	if byte >= 0xe0 and byte <= 0xff then
		return -32 + (byte - 0xe0)
	end

	return lua_typeof(byte_data) == "function" and byte_data(stream) or byte_data
end

---starts recursively deserializing the data from the first index one time
---@param data table
---@return any
function deserializer.unmarshal_one(data)
	return deserializer.at(deserializer_stream.new(data))
end

-- return deseralizer module
return deserializer
