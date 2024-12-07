---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@class handshake_stage_handler: stage_handler
---@field boot_stage_handler boot_stage_handler
---@field rc4_key number[]
---@field hmac_key number[]
---@field private_key number[]
-- handle the handshake stage
local handshake_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.networking.deserializer
local deserializer = require("lib.networking.deserializer")

---@module lib.networking.serializer
local serializer = require("lib.networking.serializer")

---@module lib.keys.curve25519
local curve25519 = require("lib.keys.curve25519")

---@module lib.utility
local utility = require("lib.utility")

---@module lib.keys.hdkf
local hdkf = require("lib.keys.hdkf")

---@module lib.digest.sha2_256
local sha2_256 = require("lib.digest.sha2_256")

---@module lib.lockbox.stream
local stream = require("lib.lockbox.stream")

---@module lib.lockbox.array
local array = require("lib.lockbox.array")

---@module lib.mac.hmac
local hmac = require("lib.mac.hmac")

---@module lib.cipher.rc4
local rc4 = require("lib.cipher.rc4")

---@module lib.stage_handlers.established_stage_handler
local established_stage_handler = require("lib.stage_handlers.established_stage_handler")

---@module lib.profiler
local profiler = require("lib.profiler")

-- constant script's sws version
local SWS_VERSION = 100

---@compile_time: script's salt
local DB_HDKF_SALT = {}

---handshake stage handler's unmarshal one message
---@param conn_data connection_data
---@param data number[]
---@return any
function handshake_stage_handler:unmarshal_one(conn_data, data)
	return profiler.run_function("ArmorShield_UnmarshalOne", function()
		local mac_bytes = nil
		local cipher_text = nil

		profiler.run_function("ArmorShield_SliceMessage", function()
			mac_bytes = array.slice(data, 1, 32)
			cipher_text = array.slice(data, 33, #data)
		end)

		local mac_object = hmac.new(64, sha2_256, self.hmac_key)
		local timestamp_bytes = utility.number_to_le_bytes(self.boot_stage_handler.timestamp, false)

		profiler.run_function("ArmorShield_TagMessage", function()
			mac_object:update(stream.from_array(cipher_text))
			mac_object:update(stream.from_number(SWS_VERSION))
			mac_object:update(stream.from_string(timestamp_bytes))
			mac_object:update(stream.from_array(self.boot_stage_handler.subscription_id))
		end)

		local comparison = nil

		profiler.run_function("ArmorShield_CompareMessage", function()
			comparison = utility.compare_tbl(mac_object:finish():as_bytes(), mac_bytes)
		end)

		if not comparison then
			return conn_data:disconnect("signature fail")
		end

		local rc4_object = rc4.new(self.rc4_key)

		local decrypted_msg = profiler.run_function("ArmorShield_ProcessMessage", function()
			return rc4_object:run(cipher_text)
		end)

		local ret = profiler.run_function("ArmorShield_UnmarshalMessage", function()
			return deserializer.unmarshal_one(decrypted_msg)
		end)

		return ret
	end)
end

---handshake stage handler's send message
---@param conn_data connection_data
---@param id packet_id
---@param data table
function handshake_stage_handler:send_message(conn_data, id, data)
	return profiler.run_function("ArmorShield_SendMessage", function()
		local msg = profiler.run_function("ArmorShield_MarshalMessage", function()
			return serializer.marshal(data)
		end)

		local rc4_object = rc4.new(self.rc4_key)

		local encrypted_msg = profiler.run_function("ArmorShield_ProcessMessage", function()
			return rc4_object:run(utility.to_byte_array(msg))
		end)

		local mac_object = hmac.new(64, sha2_256, self.hmac_key)
		local mac = nil

		profiler.run_function("ArmorShield_TagMessage", function()
			mac_object:update(stream.from_array(encrypted_msg))
			mac_object:update(stream.from_number(SWS_VERSION))
			mac_object:update(stream.from_string(utility.number_to_le_bytes(self.boot_stage_handler.timestamp, false)))
			mac_object:update(stream.from_array(self.boot_stage_handler.subscription_id))
			mac = mac_object:finish():as_bytes()
		end)

		local final_byte_array = {}

		profiler.run_function("ArmorShield_PrepareMessage", function()
			utility.append_tbl(final_byte_array, mac)
			utility.append_tbl(final_byte_array, encrypted_msg)
		end)

		profiler.run_function("ArmorShield_SendPacket", function()
			conn_data:send_packet(id, utility.to_string(final_byte_array))
		end)
	end)
end

---handshake stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function handshake_stage_handler:handle_packet(conn_data, pk)
	local handshake_msg = deserializer.unmarshal_one(pk.Msg)
	local shared_key =
		utility.shift(curve25519.X25519(self.private_key, utility.shift(handshake_msg["ServerPublicKey"], -1)), 1)

	self.rc4_key = hdkf.new(shared_key, DB_HDKF_SALT, sha2_256, { 0x00 }, 16):finish():as_bytes()
	self.hmac_key = hdkf.new(shared_key, DB_HDKF_SALT, sha2_256, { 0x01 }, 32):finish():as_bytes()

	conn_data.stage_handler = established_stage_handler.new(self)
	conn_data.handshake_stage_handler = self
	conn_data:set_client_stage(2)

	self:send_message(conn_data, 2, {
		["SubId"] = self.boot_stage_handler.subscription_id,
		["BaseTimestamp"] = self.boot_stage_handler.timestamp,
	})
end

---handshake stage handler's packet id
---@return packet_id
function handshake_stage_handler:handle_packet_id()
	return 1
end

---handshake stage handler's client stage
---@return client_stage
function handshake_stage_handler:handle_client_stage()
	return 1
end

---new handshake stage handler object
---@param private_key number[]
---@param boot_stage_handler boot_stage_handler
---@return handshake_stage_handler
function handshake_stage_handler.new(private_key, boot_stage_handler)
	-- create handshake handler object
	local self = setmetatable(stage_handler.new(), { __index = handshake_stage_handler })
	self.private_key = private_key
	self.boot_stage_handler = boot_stage_handler

	-- return handshake handler object
	return self
end

-- return handshake stage handler module
return handshake_stage_handler
