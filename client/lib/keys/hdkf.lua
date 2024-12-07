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

---@class hdkf
---@field input_key_material number[]
---@field salt number[]
---@field digest digest
---@field info number[]?
---@field output_len number
---@field hash_len number
---@field secret number[]
local hdkf = {}

---@module lib.mac.hmac
local hmac = require("lib.mac.hmac")

---@module lib.lockbox.stream
local stream = require("lib.lockbox.stream")

-- default salt constant
local DEFAULT_SALT = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

---expand hdkf bytes
---@param prk number[]
---@return number
function hdkf:expand(prk)
	local iterations = math.ceil(self.output_len / self.hash_len)
	local remaining_bytes = self.output_len
	local mixin = {}
	local results = {}

	for i = 1, iterations do
		local mac = hmac.new(64, self.digest, prk)

		mac:update(stream.from_array(mixin))

		if self.info then
			mac:update(stream.from_array(self.info))
		end

		mac:update(stream.from_array({ i }))

		local step_result = mac:finish():as_bytes()
		local step_size = math.min(remaining_bytes, #step_result)

		for j = 1, step_size do
			results[#results + 1] = step_result[j]
		end

		mixin = step_result
		remaining_bytes = remaining_bytes - step_size
	end

	return results
end

---extract hdkf bytes
---@return number[]
function hdkf:extract()
	local hmac_object = hmac.new(64, self.digest, self.salt)
	local res = hmac_object:update(stream.from_array(self.input_key_material)):finish():as_bytes()
	self.hash_len = #res
	return res
end

---finish hdkf and extract & process secret
---@return hdkf
function hdkf:finish()
	local prk = self:extract()
	self.secret = self:expand(prk)
	return self
end

---fetch secret bytes
---@return number[]
function hdkf:as_bytes()
	return self.secret
end

---new hdkf object
---@param input_key_material number[]
---@param salt number[]|nil
---@param digest digest
---@param info number[]|nil
---@param output_len number
---@return hdkf
function hdkf.new(input_key_material, salt, digest, info, output_len)
	-- create new hdkf object
	local self = setmetatable({}, { __index = hdkf })
	self.input_key_material = input_key_material
	self.salt = salt or DEFAULT_SALT
	self.digest = digest
	self.info = info
	self.output_len = output_len

	-- return new hdkf object
	return self
end

-- return new hdkf object
return hdkf
