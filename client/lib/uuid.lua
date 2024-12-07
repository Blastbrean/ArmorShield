-- uuid module
local uuid = {}

-- cached functions
local string_byte = string.byte

---@module lib.utility
local utility = require("lib.utility")

---@module lib.lockbox.array
local array = require("lib.lockbox.array")

---convert the UUID into a hex string
---@param uuid_data number[16]
---@return string
function uuid.hex_string(uuid_data)
	local hex_uuid = {}
	utility.hex_encode(hex_uuid, array.slice(uuid_data, 1, 4))

	---merge current uuid with a slice piece
	---@param dst number[]
	---@param src number[]
	---@param en_start number
	---@param en_end number
	local function encode_slice(dst, src, en_start, en_end)
		local hex_slice = array.slice(dst, en_start, en_end)
		utility.hex_encode(hex_slice, src)

		for idx, byte in next, hex_slice do
			hex_uuid[en_start + idx - 1] = byte
		end
	end

	encode_slice(hex_uuid, array.slice(uuid_data, 5, 6), 10, 14)
	encode_slice(hex_uuid, array.slice(uuid_data, 7, 8), 15, 19)
	encode_slice(hex_uuid, array.slice(uuid_data, 9, 10), 20, 24)
	encode_slice(hex_uuid, array.slice(uuid_data, 11, #uuid_data), 25, #hex_uuid)

	hex_uuid[9] = string_byte("-")
	hex_uuid[14] = string_byte("-")
	hex_uuid[19] = string_byte("-")
	hex_uuid[24] = string_byte("-")

	return utility.to_string(hex_uuid)
end
-- return uuid module
return uuid
