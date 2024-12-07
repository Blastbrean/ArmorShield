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

-- array module
local array = {}

-- cached functions
local bit32_bxor = bit32.bxor

---xor two arrays together
---@param a number[]
---@param b number[]
---@return number[]
array.xor = LPH_NO_VIRTUALIZE(function(a, b)
	local out = {}

	for k, v in pairs(a) do
		out[k] = bit32_bxor(v, b[k])
	end

	return out
end)

---substitute keys for values in sbox
---@param input number[]
---@param sbox number[]
---@return number[]
array.substitute = LPH_NO_VIRTUALIZE(function(input, sbox)
	local out = {}

	for k, v in pairs(input) do
		out[k] = sbox[v]
	end

	return out
end)

---read from queue to array
---@param queue queue
---@param size number
---@return table
array.read_from_queue = LPH_NO_VIRTUALIZE(function(queue, size)
	local arr = {}

	for i = 1, size do
		arr[i] = queue:pop()
	end

	return arr
end)

---write array to queue
---@param queue queue
---@param arr table
array.write_to_queue = LPH_NO_VIRTUALIZE(function(queue, arr)
	local size = #arr

	for i = 1, size do
		queue:push(arr[i])
	end
end)

---permute keys for values from pbox
---@param input number[]
---@param sbox number[]
---@return number[]
array.permute = LPH_NO_VIRTUALIZE(function(input, sbox)
	local out = {}

	for k, v in pairs(sbox) do
		out[k] = input[v]
	end

	return out
end)

---copy array (shallow)
---@param input number[]
---@return number[]
array.copy = LPH_NO_VIRTUALIZE(function(input)
	local out = {}

	for k, v in pairs(input) do
		out[k] = v
	end

	return out
end)

---take a chunk out of an array into a new array
---@param input number[]
---@param start number
---@param stop number
---@return number[]
array.slice = LPH_NO_VIRTUALIZE(function(input, start, stop)
	local out = {}

	if start == nil then
		start = 1
	elseif start < 0 then
		start = #input + start + 1
	end
	if stop == nil then
		stop = #input
	elseif stop < 0 then
		stop = #input + stop + 1
	end

	for i = start, stop do
		table.insert(out, input[i])
	end

	return out
end)

-- return array module
return array
