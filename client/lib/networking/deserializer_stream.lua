---@class deserializer_stream
local deserializer_stream = {}

---@module lib.utility
local utility = require("lib.utility")

---@module lib.logger
local logger = require("lib.logger")

-- cached functions
local bit32_bor, bit32_lshift, bit32_band, bit32_rshift = bit32.bor, bit32.lshift, bit32.band, bit32.rshift

---read bytes in little endian
---@param len number
---@return number[]
function deserializer_stream:le_read_bytes(len)
	local bytes = {}

	for idx = self.index + 1, self.index + len do
		bytes[#bytes + 1] = self.source[idx]
	end

	self.index = self.index + len

	if self.index > #self.source then
		return logger.fatal("le read overflow")
	end

	return bytes
end

---read bytes in big endianess format
---@param len number
---@return number[]
function deserializer_stream:be_read_bytes(len)
	local bytes = {}

	for idx = self.index + len, self.index + 1, -1 do
		bytes[#bytes + 1] = self.source[idx]
	end

	self.index = self.index + len

	if self.index > #self.source then
		return logger.fatal("be read overflow")
	end

	return bytes
end

---read string (inlined le_read_bytes, need more optimizations)
---@param len number
---@return string
deserializer_stream.string = LPH_NO_VIRTUALIZE(function(self, len)
	local src = self.source

	---@reversal: without this - the code will be so slow because of 400k+ concat instructions!
	---also, LPH_NO_VIRTUALIZE calls exposing everything (but i want <5s loads - and it worked well enough in the last loader.) :(

	local buf = buffer.create(len)

	for idx = self.index + 1, self.index + len do
		buffer.writeu8(buf, idx - self.index - 1, src[idx])
	end

	self.index = self.index + len

	if self.index > #self.source then
		return logger.fatal("le read overflow")
	end

	return buffer.readstring(buf, 0, len)
end)

---read unsigned long
---@return number
function deserializer_stream:unsigned_long()
	local bytes = self:be_read_bytes(8)
	local p1 = bit32_bor(bytes[1], bit32_lshift(bytes[2], 8), bit32_lshift(bytes[3], 16), bit32_lshift(bytes[4], 24))
	local p2 = bit32_bor(bytes[5], bit32_lshift(bytes[6], 8), bit32_lshift(bytes[7], 16), bit32_lshift(bytes[8], 24))
	return bit32_bor(p1, bit32_lshift(p2, 32))
end

---read unsigned int
---@return number
function deserializer_stream:unsigned_int()
	local bytes = self:be_read_bytes(4)
	return bit32_bor(bytes[1], bit32_lshift(bytes[2], 8), bit32_lshift(bytes[3], 16), bit32_lshift(bytes[4], 24))
end

---read unsigned short
---@return number
function deserializer_stream:unsigned_short()
	local bytes = self:be_read_bytes(2)
	return bit32_bor(bytes[1], bit32_lshift(bytes[2], 8))
end

---read float
---@return number
function deserializer_stream:float()
	local bytes = self:be_read_bytes(4)
	local sign = (-1) ^ bit32_rshift(bytes[4], 7)
	local exp = bit32_rshift(bytes[3], 7) + bit32_lshift(bit32_band(bytes[4], 0x7F), 1)
	local frac = bytes[1] + bit32_lshift(bytes[2], 8) + bit32_lshift(bit32_band(bytes[3], 0x7F), 16)
	local normal = 1

	if exp == 0 then
		if frac == 0 then
			return sign * 0
		else
			normal = 0
			exp = 1
		end
	elseif exp == 0x7F then
		if frac == 0 then
			return sign * (1 / 0)
		else
			return sign * (0 / 0)
		end
	end

	return sign * 2 ^ (exp - 127) * (1 + normal / 2 ^ 23)
end

---read double
function deserializer_stream:double()
	local bytes = self:be_read_bytes(8)
	local sign = (-1) ^ bit32_rshift(bytes[8], 7)
	local exp = bit32_lshift(bit32_band(bytes[8], 0x7F), 4) + bit32_rshift(bytes[7], 4)
	local frac = bit32_band(bytes[7], 0x0F) * 2 ^ 48
	local normal = 1

	frac = frac
		+ (bytes[6] * 2 ^ 40)
		+ (bytes[5] * 2 ^ 32)
		+ (bytes[4] * 2 ^ 24)
		+ (bytes[3] * 2 ^ 16)
		+ (bytes[2] * 2 ^ 8)
		+ bytes[1]

	if exp == 0 then
		if frac == 0 then
			return sign * 0
		else
			normal = 0
			exp = 1
		end
	elseif exp == 0x7FF then
		if frac == 0 then
			return sign * (1 / 0)
		else
			return sign * (0 / 0)
		end
	end

	return sign * 2 ^ (exp - 1023) * (normal + frac / 2 ^ 52)
end

---read long
---@return number
function deserializer_stream:long()
	local value = self:unsigned_long()

	if bit32_band(value, 0x8000000000000000) ~= 0x0 then
		value = value - 0x800000000000000
	end

	return value
end

---read int
---@return number
function deserializer_stream:int()
	local value = self:unsigned_int()

	if bit32_band(value, 0x80000000) ~= 0 then
		value = value - 0x100000000
	end

	return value
end

---read short
---@return number
function deserializer_stream:short()
	local value = self:unsigned_short()

	if bit32_band(value, 0x8000) ~= 0 then
		value = value - 0x10000
	end

	return value
end

---read byte
function deserializer_stream:byte()
	local bytes = self:le_read_bytes(1)
	return bytes[1]
end

---new deserializer stream object
---@param source table
---@return deserializer_stream
function deserializer_stream.new(source)
	-- create new deserializer stream object
	local self = setmetatable({}, { __index = deserializer_stream })
	self.source = source
	self.index = 0

	-- return new deserializer stream object
	return self
end

-- return deserializer stream module
return deserializer_stream
