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

-- stream module
local stream = {}

---@module lib.lockbox.queue
local queue = require("lib.lockbox.queue")

---turn a number into a stream
---@param num number
---@return function
stream.from_number = LPH_NO_VIRTUALIZE(function(num)
	local i = 0
	return function()
		i = i + 1
		return i <= 1 and num or nil
	end
end)

---turn a string into a stream
---@param str string
---@return function
stream.from_string = LPH_NO_VIRTUALIZE(function(str)
	local i = 0
	return function()
		i = i + 1
		return str:byte(i)
	end
end)

---turn an array into a stream - popping the queue every time it's called
---@param array table
---@return function
stream.from_array = LPH_NO_VIRTUALIZE(function(array)
	local current_queue = queue.new()
	local i = 1

	local byte = array[i]
	while byte ~= nil do
		current_queue:push(byte)
		i = i + 1
		byte = array[i]
	end

	return function()
		return current_queue:pop()
	end
end)

---turn a stream into an array
---@param stream_func function
---@return table
stream.to_array = LPH_NO_VIRTUALIZE(function(stream_func)
	local array = {}
	local i = 1

	local byte = stream_func()
	while byte ~= nil do
		array[i] = byte
		i = i + 1
		byte = stream_func()
	end

	return array
end)

-- return stream module
return stream
