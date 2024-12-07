-- cached functions
local profile_begin, table_pack, profile_end, lua_unpack = debug.profilebegin, table.pack, debug.profileend, unpack

-- profile code time: possibly in order to get code which is possibly lagging us, which can be viewed under the microprofiler.
local profiler = {}

---runs a function with a specified profiler label
---@param label string
---@param function_to_profile function
function profiler.run_function(label, function_to_profile, ...)
	-- profile under label
	profile_begin(label)

	-- call function to profile
	local ret_values = table_pack(function_to_profile(...))

	-- and end most recent profiling (which is most likely the one we just created)
	profile_end()

	-- return values
	return lua_unpack(ret_values)
end

---wraps function in a profiler statement with label
---@param label string
---@param function_to_profile function
---@return function
function profiler.wrap_function(label, function_to_profile)
	-- return wrapped function
	return function(...)
		return profiler.run_function(label, function_to_profile, ...)
	end
end

-- return profiler module
return profiler
