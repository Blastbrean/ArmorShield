--[[
 * MessagePack serializer / decode (0.6.1) written in pure Lua 5.3 / Lua 5.4
 * written by Sebastian Steinhauer <s.steinhauer@yahoo.de>
 * modified by the Lycoris Team <discord.gg/lyc>
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
]]

-- serializer module
local serializer = {}

-- cached functions
local table_concat = table.concat
local string_pack, string_unpack = string.pack, string.unpack
local utf8_len = utf8.len

---does a specified table match the layout of an array
---@param tbl table
---@return boolean
local function is_an_array(tbl)
	local expected = 1

	for k in next, tbl do
		if k ~= expected then
			return false
		end

		expected = expected + 1
	end

	return true
end

---serialize number to a float
---@param value number
---@return string
local function serialize_float(value)
	local serialized_float = string_unpack("f", string_pack("f", value))
	if serialized_float == value then
		return string_pack(">Bf", 0xca, value)
	end

	return string_pack(">Bd", 0xcb, value)
end

---serialize number to a signed int
---@param value number
---@return string
local function serialize_signed_int(value)
	if value < 128 then
		return string_pack("B", value)
	elseif value <= 0xff then
		return string_pack("BB", 0xcc, value)
	elseif value <= 0xffff then
		return string_pack(">BI2", 0xcd, value)
	elseif value <= 0xffffffff then
		return string_pack(">BI4", 0xce, value)
	end

	return string_pack(">BI8", 0xcf, value)
end

---serialize number to a unsigned int
---@param value number
---@return string
local function serialize_unsigned_int(value)
	if value >= -32 then
		return string_pack("B", 0xe0 + (value + 32))
	elseif value >= -128 then
		return string_pack("Bb", 0xd0, value)
	elseif value >= -32768 then
		return string_pack(">Bi2", 0xd1, value)
	elseif value >= -2147483648 then
		return string_pack(">Bi4", 0xd2, value)
	end

	return string_pack(">Bi8", 0xd3, value)
end

---serialize string to a utf8 string
---@param value string
---@return string
local function serialize_utf8(value)
	local len = #value

	if len < 32 then
		return string_pack("B", 0xa0 + len) .. value
	elseif len < 256 then
		return string_pack(">Bs1", 0xd9, value)
	elseif len < 65536 then
		return string_pack(">Bs2", 0xda, value)
	end

	return string_pack(">Bs4", 0xdb, value)
end

---serialize string to a string of bytes
---@param value string
---@return string
local function serialize_string_bytes(value)
	local len = #value

	if len < 256 then
		return string_pack(">Bs1", 0xc4, value)
	elseif len < 65536 then
		return string_pack(">Bs2", 0xc5, value)
	end

	return string_pack(">Bs4", 0xc6, value)
end

---serialize table to a array
---@param value table
---@return string
local function serialize_array(value)
	local elements = {}

	for i, v in pairs(value) do
		if type(v) ~= "function" and type(v) ~= "thread" and type(v) ~= "userdata" then
			elements[i] = serializer.marshal(v)
		end
	end


	local result = nil

	for i = 0, #elements do
		result = (result or "") .. elements[i]
	end

	local length = #elements

	length = length + 1

	if length < 16 then
		return string_pack(">B", 0x90 + length) .. result
	elseif length < 65536 then
		return string_pack(">BI2", 0xdc, length) .. result
	end

	return string_pack(">BI4", 0xdd, length) .. result
end

---serialize table to a map
---@param value table
---@return string
local function serialize_map(value)
	local elements = {}

	for k, v in pairs(value) do
		if type(v) ~= "function" and type(v) ~= "thread" and type(v) ~= "userdata" then
			elements[#elements + 1] = serializer.marshal(k)
			elements[#elements + 1] = serializer.marshal(v)
		end
	end

	local length = math.floor(#elements / 2)
	if length < 16 then
		return string_pack(">B", 0x80 + length) .. table_concat(elements)
	elseif length < 65536 then
		return string_pack(">BI2", 0xde, length) .. table_concat(elements)
	end

	return string_pack(">BI4", 0xdf, length) .. table_concat(elements)
end

---serialize nil to a binary string
---@return string
local function serialize_nil()
	return string_pack("B", 0xc0)
end

---serialize table to a binary string
---@param value table
---@return string
local function serialize_table(value)
	return is_an_array(value) and serialize_array(value) or serialize_map(value)
end

---serialize boolean to a binary string
---@param value boolean
---@return string
local function serialize_boolean(value)
	return string_pack("B", value and 0xc3 or 0xc2)
end

---serialize int to a binary string
---@param value number
---@return string
local function serialize_int(value)
	return value >= 0 and serialize_signed_int(value) or serialize_unsigned_int(value)
end

---serialize number to a binary string
---@param value number
---@return string
local function serialize_number(value)
	return value % 1 == 0 and serialize_int(value) or serialize_float(value)
end

---serialize string to a binary string
---@param value number
---@return string
local function serialize_string(value)
	return utf8_len(value) and serialize_utf8(value) or serialize_string_bytes(value)
end

-- types mapping to functions that serialize it
local type_to_serialize_map = {
	["nil"] = serialize_nil,
	["boolean"] = serialize_boolean,
	["number"] = serialize_number,
	["string"] = serialize_string,
	["table"] = serialize_table,
}

---marshal a value into a binary string
---@param value any
---@return string
function serializer.marshal(value)
	return type_to_serialize_map[type(value)](value)
end

-- return serializer module
return serializer
