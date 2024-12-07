---@class rc4
---@field x number
---@field y number
---@field st table
---@note: https://github.com/CheyiLin/lrc4/blob/master/rc4.lua
local rc4 = {}

-- cached functions
local bit32_bxor = bit32.bxor

---run rc4 on data w/ key (must be 16 bytes)
---@param data table
---@return table
rc4.run = LPH_NO_VIRTUALIZE(function(self, data)
	local x, y, st = self.x, self.y, self.st

	local t = {}

	for i = 1, #data do
		x = (x + 1) % 256
		y = (y + st[x]) % 256
		st[x], st[y] = st[y], st[x]
		t[i] = bit32_bxor(data[i], st[(st[x] + st[y]) % 256])
	end

	self.x, self.y = x, y

	return t
end)

---new rc4 object
---@param key table
---@return rc4
function rc4.new(key)
	local self = setmetatable({}, { __index = rc4 })
	self.x = 0
	self.y = 0

	local st = {}

	for i = 0, 255 do
		st[i] = i
	end

	local len = #key
	local j = 0

	for i = 0, 255 do
		j = (j + st[i] + key[(i % len) + 1]) % 256
		st[i], st[j] = st[j], st[i]
	end

	self.st = st

	return self
end

-- return rc4 module
return rc4
