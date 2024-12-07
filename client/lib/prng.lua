--------------------------------------------------------------------------------------------------------
-- This code snippet implements pseudo-random number generator

-- Output: 32-bit integers 0..4294967295
-- Internal state (seed): 53 bits, can be read or write at any time
-- Good statistical properties of PRN sequence:
--    uniformity,
--    long period of 255 * 2^45 (approximately 2^53),
--    unpredictability

-- Compatible with Lua 5.1, 5.2, 5.3, LuaJIT
--------------------------------------------------------------------------------------------------------

-- prng module
local prng = {}

-- cached functions
local math_floor = math.floor

-- all parameters in PRNG formula are derived from these 57 secret bits:
local secret_key_6 = 58 -- 6-bit arbitrary integer (0..63)
local secret_key_7 = 110 -- 7-bit arbitrary integer (0..127)
local secret_key_44 = 3580861008710 -- 44-bit arbitrary integer (0..17592186044415)

---primitive root modulo 257 (one of 128 existing roots, idx = 0..127)
---@param idx number
---@return number
local function primitive_root_257(idx)
	local g, m, d = 1, 128, 2 * idx + 1

	repeat
		g, m, d = g * g * (d >= m and 3 or 1) % 257, m / 2, d % m
	until m < 1

	return g
end

-- derive parameters
local param_mul_8 = primitive_root_257(secret_key_7)
local param_mul_45 = secret_key_6 * 4 + 1
local param_add_45 = secret_key_44 * 2 + 1

-- seed (53-bit integer)
local SEED_NUMBER = os.clock()

-- state_45: from 0 to (2^45-1), state_8: from 2 to 256
local state_45 = SEED_NUMBER % 35184372088832
local state_8 = math_floor(SEED_NUMBER / 35184372088832) % 255 + 2

---get a random 32-bit number
---@return number
function prng.get_random()
	state_45 = (state_45 * param_mul_45 + param_add_45) % 35184372088832

	repeat
		state_8 = state_8 * param_mul_8 % 257
	until state_8 ~= 1

	local r = state_8 % 32
	local n = math_floor(state_45 / 2 ^ (13 - (state_8 - r) / 32)) % 2 ^ 32 / 2 ^ r
	return math_floor(n % 1 * 2 ^ 32) + math_floor(n)
end

---get a random byte table
---@param length number
---@return number[]
function prng.get_byte_table(length)
	local byte_table = {}

	for i = 1, length do
		byte_table[i] = prng.get_random() % 255
	end

	return byte_table
end

-- return prng module
return prng
