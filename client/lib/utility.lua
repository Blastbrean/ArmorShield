---generate byte mapping to char
---@return table
local function generate_byte_char_map()
	local byte_char_table = {}

	for i = 0, 255 do
		byte_char_table[i] = string.char(i)
	end

	return byte_char_table
end

---generate char mapping to byte
---@return table
local function generate_char_byte_map()
	local char_byte_table = {}

	for i = 0, 255 do
		char_byte_table[string.char(i)] = i
	end

	return char_byte_table
end

-- utility module
local utility = {
	byte_char_map = generate_byte_char_map(),
	char_byte_map = generate_char_byte_map(),
	hex_encoding = "0123456789abcdef",
}

-- cached functions
local string_byte, bit32_rshift, bit32_band = string.byte, bit32.rshift, bit32.band

---byte array to string
---@param bytes number[]
---@return string
utility.to_string = LPH_NO_VIRTUALIZE(function(bytes)
	local str = ""
	local i = 1

	local byte = bytes[i]

	while byte ~= nil do
		str = str .. utility.byte_char_map[byte]
		i = i + 1
		byte = bytes[i]
	end

	return str
end)

---append the values from one table to another
---@param to_tbl any
---@param from_tbl any
utility.append_tbl = LPH_NO_VIRTUALIZE(function(to_tbl, from_tbl)
	for _, value in next, from_tbl do
		table.insert(to_tbl, value)
	end
end)

---hex encode bytes
---@param dst number[]
---@param src number[]
function utility.hex_encode(dst, src)
	local idx = 1

	for _, byte in next, src do
		dst[idx] = string_byte(utility.hex_encoding, bit32_rshift(byte, 4) + 1)
		dst[idx + 1] = string_byte(utility.hex_encoding, bit32_band(byte, 0x0F) + 1)
		idx = idx + 2
	end
end

---shift table indexes
---@param tbl table
---@param shift number
---@return table
function utility.shift(tbl, shift)
	local shifted_table = {}

	for idx, value in next, tbl do
		shifted_table[idx + shift] = value
	end

	return shifted_table
end

---string to byte array
---@param str string
---@return string
function utility.to_byte_array(str)
	local chars = {}
	local i = 1

	repeat
		chars[i] = utility.char_byte_map[str:sub(i, i)]
		i = i + 1
	until i == #str + 1

	return chars
end

---compare two tables and check if all values match
---@param a table
---@param b table
function utility.compare_tbl(a, b)
	if #a ~= #b then
		return false
	end

	for index, value in next, a do
		if value ~= b[index] then
			return false
		end
	end

	return true
end

---convert number to little endian bytes (https://stackoverflow.com/questions/5241799/lua-dealing-with-non-ascii-byte-streams-byteorder-change)
---@param num number
---@param signed boolean
---@return string
function utility.number_to_le_bytes(num, signed)
	if num < 0 and not signed then
		num = -num
	end

	local res = {}
	local n = math.ceil(select(2, math.frexp(num)) / 8)
	if signed and num < 0 then
		num = num + 2 ^ n
	end

	for k = n, 1, -1 do
		local mul = 2 ^ (8 * (k - 1))
		res[k] = math.floor(num / mul)
		num = num - res[k] * mul
	end

	for i = 1, 8 do
		if not res[i] then
			res[i] = 0x00
		end
	end

	return string.char(unpack(res))
end

-- return utility module
return utility
