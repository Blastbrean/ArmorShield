-- https://github.com/somesocks/lua-lockbox/

--[[
The MIT License (MIT)

Copyright (c) 2015 James L.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

---@class hmac
---@field outer_padding table
---@field inner_padding table
---@field digest digest
---@field block_size number
local hmac = {}

---@module lib.lockbox.stream
local stream = require("lib.lockbox.stream")

-- cached functions
local bit32_bxor = bit32.bxor

---create padding from key
---@param key number[]
hmac.create_padding = LPH_NO_VIRTUALIZE(function(self, key)
	local key_stream = nil

	if #key > self.block_size then
		key_stream = stream.from_array(self.digest.new():update(stream.from_array(key)):finish():as_bytes())
	else
		key_stream = stream.from_array(key)
	end

	for i = 1, self.block_size do
		local byte = key_stream()

		if byte == nil then
			byte = 0x00
		end

		self.outer_padding[i] = bit32_bxor(0x5C, byte)
		self.inner_padding[i] = bit32_bxor(0x36, byte)
	end
end)

---update hmac digest
---@param message_stream function
---@return hmac
function hmac:update(message_stream)
	self.digest:update(message_stream)
	return self
end

---finish and process hmac digest
---@return hmac
function hmac:finish()
	local inner = self.digest:finish():as_bytes()

	self.digest =
		self.digest:new():update(stream.from_array(self.outer_padding)):update(stream.from_array(inner)):finish()

	return self
end

---return digest bytes
---@return number[]
function hmac:as_bytes()
	return self.digest:as_bytes()
end

---new hmac object
---@param block_size number|nil
---@param digest_module digest
---@param key number[]
---@return hmac
function hmac.new(block_size, digest_module, key)
	-- create new hmac object
	local self = setmetatable({}, { __index = hmac })
	self.block_size = block_size or 64
	self.digest = digest_module.new()
	self.outer_padding = {}
	self.inner_padding = {}
	self:create_padding(key)
	self.digest:update(stream.from_array(self.inner_padding))

	-- return new hmac object
	return self
end

-- return hmac module
return hmac
