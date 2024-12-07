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

---@module lib.digest.digest
local digest = require("lib.digest.digest")

---@class sha2_256: digest
---@field queue queue
---@field h0 number
---@field h1 number
---@field h2 number
---@field h3 number
---@field h4 number
---@field h5 number
---@field h6 number
---@field h7 number
local sha2_256 = setmetatable({}, { __index = digest })

---@module lib.lockbox.queue
local queue = require("lib.lockbox.queue")

-- constans for sha2-256
local SHA2_256_CONSTANTS = {
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
}

-- cached functions
local bit32_band = bit32.band
local bit32_bor = bit32.bor
local bit32_bnot = bit32.bnot
local bit32_bxor = bit32.bxor
local bit32_rrotate = bit32.rrotate
local bit32_lshift = bit32.lshift
local bit32_rshift = bit32.rshift

---big-endian bytes to word
---@param b0 number
---@param b1 number
---@param b2 number
---@param b3 number
---@return number
local bytes_to_word = LPH_NO_VIRTUALIZE(function(b0, b1, b2, b3)
	local i = b0

	i = bit32_lshift(i, 8)
	i = bit32_bor(i, b1)
	i = bit32_lshift(i, 8)
	i = bit32_bor(i, b2)
	i = bit32_lshift(i, 8)
	i = bit32_bor(i, b3)

	return i
end)

---word to big-endian bytes
---@param word number
---@return number, number, number, number
local word_to_bytes = LPH_NO_VIRTUALIZE(function(word)
	local b1, b2, b3

	b3 = bit32_band(word, 0xFF)
	word = bit32_rshift(word, 8)

	b2 = bit32_band(word, 0xFF)
	word = bit32_rshift(word, 8)

	b1 = bit32_band(word, 0xFF)
	word = bit32_rshift(word, 8)

	return bit32_band(word, 0xFF), b1, b2, b3
end)

---dword to big-endian bytes
---@param i number
---@return number, number, number, number, number, number, number, number
local dword_to_bytes = LPH_NO_VIRTUALIZE(function(i)
	local b4, b5, b6, b7 = word_to_bytes(i)
	local b0, b1, b2, b3 = word_to_bytes(math.floor(i / 0x100000000))
	return b0, b1, b2, b3, b4, b5, b6, b7
end)

---process block
sha2_256.process_block = LPH_NO_VIRTUALIZE(function(self)
	local current_queue = self.queue
	local a = self.h0
	local b = self.h1
	local c = self.h2
	local d = self.h3
	local e = self.h4
	local f = self.h5
	local g = self.h6
	local h = self.h7
	local w = {}

	for i = 0, 15 do
		w[i] = bytes_to_word(current_queue:pop(), current_queue:pop(), current_queue:pop(), current_queue:pop())
	end

	for i = 16, 63 do
		local s0 = bit32_bxor(
			bit32_rrotate(w[i - 15], 7),
			bit32_bxor(bit32_rrotate(w[i - 15], 18), bit32_rshift(w[i - 15], 3))
		)

		local s1 =
			bit32_bxor(bit32_rrotate(w[i - 2], 17), bit32_bxor(bit32_rrotate(w[i - 2], 19), bit32_rshift(w[i - 2], 10)))

		w[i] = bit32_band(w[i - 16] + s0 + w[i - 7] + s1, 0xFFFFFFFF)
	end

	for i = 0, 63 do
		local s1 = bit32_bxor(bit32_rrotate(e, 6), bit32_bxor(bit32_rrotate(e, 11), bit32_rrotate(e, 25)))
		local ch = bit32_bxor(bit32_band(e, f), bit32_band(bit32_bnot(e), g))
		local temp1 = h + s1 + ch + SHA2_256_CONSTANTS[i + 1] + w[i]
		local s0 = bit32_bxor(bit32_rrotate(a, 2), bit32_bxor(bit32_rrotate(a, 13), bit32_rrotate(a, 22)))
		local maj = bit32_bxor(bit32_band(a, b), bit32_bxor(bit32_band(a, c), bit32_band(b, c)))
		local temp2 = s0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	end

	self.h0 = bit32_band(self.h0 + a, 0xFFFFFFFF)
	self.h1 = bit32_band(self.h1 + b, 0xFFFFFFFF)
	self.h2 = bit32_band(self.h2 + c, 0xFFFFFFFF)
	self.h3 = bit32_band(self.h3 + d, 0xFFFFFFFF)
	self.h4 = bit32_band(self.h4 + e, 0xFFFFFFFF)
	self.h5 = bit32_band(self.h5 + f, 0xFFFFFFFF)
	self.h6 = bit32_band(self.h6 + g, 0xFFFFFFFF)
	self.h7 = bit32_band(self.h7 + h, 0xFFFFFFFF)
end)

---update with new bytes
---@param message_stream function
---@return sha2_256
sha2_256.update = LPH_NO_VIRTUALIZE(function(self, message_stream)
	for b in message_stream do
		self.queue:push(b)

		if self.queue:size() >= 64 then
			self:process_block()
		end
	end

	return self
end)

---finish calculations and start processing
---@return sha2_256
sha2_256.finish = LPH_NO_VIRTUALIZE(function(self)
	local current_queue = self.queue
	local bits = current_queue:get_head() * 8
	current_queue:push(0x80)

	while ((current_queue:size() + 7) % 64) < 63 do
		current_queue:push(0x00)
	end

	local b0, b1, b2, b3, b4, b5, b6, b7 = dword_to_bytes(bits)
	current_queue:push(b0)
	current_queue:push(b1)
	current_queue:push(b2)
	current_queue:push(b3)
	current_queue:push(b4)
	current_queue:push(b5)
	current_queue:push(b6)
	current_queue:push(b7)

	while current_queue:size() > 0 do
		self:process_block()
	end

	return self
end)

---sha2_256 bytes dumped to byte array
---@return number[]
function sha2_256:as_bytes()
	local b0, b1, b2, b3 = word_to_bytes(self.h0)
	local b4, b5, b6, b7 = word_to_bytes(self.h1)
	local b8, b9, b10, b11 = word_to_bytes(self.h2)
	local b12, b13, b14, b15 = word_to_bytes(self.h3)
	local b16, b17, b18, b19 = word_to_bytes(self.h4)
	local b20, b21, b22, b23 = word_to_bytes(self.h5)
	local b24, b25, b26, b27 = word_to_bytes(self.h6)
	local b28, b29, b30, b31 = word_to_bytes(self.h7)

	return {
		b0,
		b1,
		b2,
		b3,
		b4,
		b5,
		b6,
		b7,
		b8,
		b9,
		b10,
		b11,
		b12,
		b13,
		b14,
		b15,
		b16,
		b17,
		b18,
		b19,
		b20,
		b21,
		b22,
		b23,
		b24,
		b25,
		b26,
		b27,
		b28,
		b29,
		b30,
		b31,
	}
end

---new sha2_256 object
---@return sha2_256
function sha2_256.new()
	-- create new sha2_256 object
	local self = setmetatable(digest.new(), { __index = sha2_256 })
	self.queue = queue.new()
	self.h0 = 0x6a09e667
	self.h1 = 0xbb67ae85
	self.h2 = 0x3c6ef372
	self.h3 = 0xa54ff53a
	self.h4 = 0x510e527f
	self.h5 = 0x9b05688c
	self.h6 = 0x1f83d9ab
	self.h7 = 0x5be0cd19

	-- return new sha2_256 object
	return self
end

-- return sha2_256 module
return sha2_256
