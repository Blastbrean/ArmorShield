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

---@class queue
---@field contents table
---@field tail number
---@field head number
local queue = {}

---push something into the queue
---@param obj any
queue.push = LPH_NO_VIRTUALIZE(function(self, obj)
	self.contents[self.head] = obj
	self.head = self.head + 1
end)

---pop something from the queue
---@return any?
queue.pop = LPH_NO_VIRTUALIZE(function(self)
	if self.tail < self.head then
		local obj = self.contents[self.tail]
		self.contents[self.tail] = nil
		self.tail = self.tail + 1
		return obj
	else
		return nil
	end
end)

---return queue size
---@return number
queue.size = LPH_NO_VIRTUALIZE(function(self)
	return self.head - self.tail
end)

---reset queue
function queue:reset()
	self.contents = {}
	self.head = 0
	self.tail = 0
end

---get queue head
---@return number
function queue:get_head()
	return self.head
end

---get queue tail
---@return number
function queue:get_tail()
	return self.tail
end

---new queue object
---@return queue
function queue.new()
	-- create new queue object
	local self = setmetatable({}, { __index = queue })
	self.contents = {}
	self.head = 0
	self.tail = 0

	-- return new queue object
	return self
end

-- return queue module
return queue
