---@module lib.stage_handlers.stage_handler
local stage_handler = require("lib.stage_handlers.stage_handler")

---@class load_stage_handler: stage_handler
---@field analytics_stage_handler analytics_stage_handler
-- handle script loading
local load_stage_handler = setmetatable({}, { __index = stage_handler })

---@module lib.stage_handlers.key_update_stage_handler
local key_update_stage_handler = require("lib.stage_handlers.key_update_stage_handler")

-- cached functions
local get_function_env, task_defer, new_proxy, get_metatable, type_of, lua_error, os_clock =
	getfenv, task.defer, newproxy, getmetatable, typeof, error, os.clock

---@module lib.logger
local logger = require("lib.logger")

---@compile_time: script's source as a function
local SCRIPT_FUNCTIONS = {}

-- start timestamp
local start_timestamp = os_clock()

---create export
local function create_script_export(conn_data, func)
	return function(...)
		if conn_data.closed then
			return lua_error("the connection is closed")
		end

		return func(conn_data, ...)
	end
end

---armorshield export to listen for role changes
---@param conn_data connection_data
---@param func function
local function add_key_update_listener(conn_data, func)
	if type_of(func) ~= "function" then
		return lua_error("expected argument #1 to be 'function'")
	end

	conn_data.key_update_listeners[#conn_data.key_update_listeners + 1] = func
end

---load stage handler's packet handler
---@param conn_data connection_data
---@param pk packet
function load_stage_handler:handle_packet(conn_data, pk)
	logger.warn("load gate (%i, %i)", pk.Id, conn_data.current_stage)

	local load_msg = self.analytics_stage_handler.handshake_stage_handler:unmarshal_one(conn_data, pk.Msg)
	if not load_msg then
		return logger.fatal("failed to deserialize load data")
	end

	logger.warn("processing and loading script")

	local lycoris_init = {}
	lycoris_init.add_key_update_listener = create_script_export(conn_data, add_key_update_listener)
	lycoris_init.current_role = self.analytics_stage_handler.current_role
	lycoris_init.key = script_key

	local safe_exports = new_proxy(true)
	local safe_exports_mt = get_metatable(safe_exports)

	safe_exports_mt.__index = newcclosure(function(_, idx)
		return lycoris_init[idx]
	end)

	local load_function = SCRIPT_FUNCTIONS[load_msg["ScriptId"]]
	get_function_env(load_function).lycoris_init = safe_exports

	conn_data.script_function = load_function
	conn_data.lycoris_init = lycoris_init
	conn_data.key_update_stage_handler =
		key_update_stage_handler.new(self.analytics_stage_handler.handshake_stage_handler)

	logger.warn("script loaded in %.2f seconds with role %s", os_clock() - start_timestamp, lycoris_init.current_role)
end

---load stage handler's packet id
---@return packet_id
function load_stage_handler:handle_packet_id()
	return 3
end

---load stage handler's client stage
---@return client_stage
function load_stage_handler:handle_client_stage()
	return 3
end

---new load stage handler object
---@param analytics_stage_handler analytics_stage_handler
---@return load_stage_handler
function load_stage_handler.new(analytics_stage_handler)
	-- create new load stage handler object
	local self = setmetatable(stage_handler.new(), { __index = load_stage_handler })
	self.analytics_stage_handler = analytics_stage_handler

	-- return new load stage handler object
	return self
end

-- return load stage handler module
return load_stage_handler
