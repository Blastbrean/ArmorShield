-- analytics module
local analytics = {}

---@module lib.json
local json = require("lib.json")

---@module lib.logger
local logger = require("lib.logger")

---@module lib.profiler
local profiler = require("lib.profiler")

-- cached functions
local is_loaded, task_wait, math_modf, os_clock, get_service, send_request, lua_tonumber, lua_tostring, lua_pcall =
	game.IsLoaded, task.wait, math.modf, os.clock, game.GetService, request, tonumber, tostring, pcall

-- services
local players = get_service(game, "Players")
local run_service = get_service(game, "RunService")
local rbx_analytics_service = get_service(game, "RbxAnalyticsService")
local user_input_service = get_service(game, "UserInputService")
local localization_service = get_service(game, "LocalizationService")
local sound_service = get_service(game, "SoundService")
local stats_service = get_service(game, "Stats")
local log_service = get_service(game, "LogService")
local group_service = get_service(game, "GroupService")

-- analytics info functions
local get_output_devices = sound_service.GetOutputDevices
local get_input_devices = sound_service.GetInputDevices
local get_country_region_for_player_async = localization_service.GetCountryRegionForPlayerAsync
local os_date = os.date

-- fingerprint info functions
local get_hwid = gethwid
local get_device_type = user_input_service.GetDeviceType

-- session info functions
local get_play_session_id = game.GetPlaySessionId
local get_session_id = rbx_analytics_service.GetSessionId
local get_client_id = rbx_analytics_service.GetClientId
local fs_listfiles = listfiles
local fs_isfile = isfile
local fs_isfolder = isfolder
local get_log_history = log_service.GetLogHistory

-- version info functions
local get_roblox_client_channel = run_service.GetRobloxClientChannel
local get_roblox_version = run_service.GetRobloxVersion
local get_core_script_version = run_service.GetCoreScriptVersion

---truncate digits
---@param num number
---@param digits number
---@return number
local function truncate_digits(num, digits)
	local mult = 10 ^ digits
	return math_modf(num * mult) / mult
end

---fetch roblox data
---@param url string
---@return boolean, table|number
local function fetch_roblox_data(url)
	local response = nil

	while true do
		response = send_request({
			Url = url,
			Method = "GET",
			Headers = {
				["Content-Type"] = "application/json",
			},
		})

		if response.StatusCode ~= 429 then
			break
		end

		task_wait(30)
	end

	if not response or not response.Success or not response.Body then
		return false, response.StatusCode
	end

	return true, json.decode(response.Body)
end

---get friend ids...
---@param user_id number
---@return number[]
local function get_friend_ids(user_id)
	local success, response = fetch_roblox_data(("https://friends.roblox.com/v1/users/%i/friends"):format(user_id))

	if not success then
		return { ["StatusCode"] = response }
	end

	local friend_ids = {}

	for _, friend_data in pairs(response.data) do
		friend_ids[#friend_ids + 1] = friend_data.id
	end

	return friend_ids
end

---get following ids...
---@param user_id number
---@return number[]
local function get_following_ids(user_id)
	local success, response = fetch_roblox_data(("https://friends.roblox.com/v1/users/%i/followings"):format(user_id))

	if not success then
		return { ["StatusCode"] = response }
	end

	local following_ids = {}

	for _, following_data in pairs(response.data) do
		following_ids[#following_ids + 1] = following_data.id
	end

	return following_ids
end

-- get group ids...
---@param user_id number
---@return number[]
local function get_group_ids(user_id)
	local success, response =
		fetch_roblox_data(("https://groups.roblox.com/v2/users/%i/groups/roles?includeLocked=true"):format(user_id))

	if not success then
		return { ["StatusCode"] = response }
	end

	local group_ids = {}

	for _, group_data in pairs(response.data) do
		group_ids[#group_ids + 1] = group_data.groupid
	end

	return group_ids
end

---scan workspace folder recursively
---@param directory string
---@param on_file_callback function
---@param recurses number
local function scan_workspace_folder_recursive(directory, on_file_callback, recurses)
	local found_files = 0

	for _, file_path in next, fs_listfiles(directory) do
		if fs_isfile(file_path) then
			if recurses > 0 and found_files >= 15 then
				return
			end

			if not on_file_callback(file_path) then
				return
			end

			found_files = found_files + 1
		elseif fs_isfolder(file_path) then
			scan_workspace_folder_recursive(file_path, on_file_callback, recurses + 1)
		end
	end
end

---scan workspace files
---@return string[]
local function scan_workspace_files()
	local workspace_files = {}

	scan_workspace_folder_recursive("", function(path)
		if #workspace_files >= 256 then
			return false
		end

		workspace_files[#workspace_files + 1] = path

		return true
	end, 0)

	return workspace_files
end

---page iterator for friend pages - thanks, roblox (https://create.roblox.com/docs/reference/engine/classes/FriendPages)
---@param pages FriendPages
---@return thread
local function page_iterator(pages)
	return coroutine.wrap(function()
		local page_number = 1

		while true do
			for _, item in ipairs(pages:GetCurrentPage()) do
				coroutine.yield(item, page_number)
			end

			if pages.IsFinished then
				break
			end

			pages:AdvanceToNextPageAsync()

			page_number = page_number + 1
		end
	end)
end

---scan log history
---@param look_back_amount number
---@return string[]
function analytics.scan_log_history(look_back_amount)
	local log_history = {}
	local log_entries = get_log_history(log_service)

	for i = #log_entries, 1, -1 do
		local log_entry = log_entries[i]

		if utf8.len(log_entry.message) then
			continue
		end

		log_history[#log_history + 1] = log_entry.message

		if i > math.max(#log_entries - look_back_amount, 0) then
			continue
		end

		break
	end

	return log_history
end

---get key information
---@return table
function analytics.get_key_info()
	logger.warn("analytics (1) - checkpoint 1")

	local local_player = nil

	repeat
		task_wait()
	until is_loaded(game)

	repeat
		local_player = players.LocalPlayer
	until local_player ~= nil

	logger.warn("analytics (1) - checkpoint 2")

	local output_devices_ids, input_devices_ids = nil, nil

	profiler.run_function("ArmorShield_Analytics_C11", function()
		local _, output_devices_ids_, _ = get_output_devices(sound_service)
		local _, input_devices_ids_, _ = get_input_devices(sound_service)
		output_devices_ids, input_devices_ids = output_devices_ids_, input_devices_ids_
	end)

	logger.warn("analytics (1) - checkpoint 3")

	local frame_rate_manager = stats_service:WaitForChild("FrameRateManager")
	local video_memory_in_mb = frame_rate_manager:WaitForChild("VideoMemoryInMB")

	local table_address = lua_tonumber(lua_tostring({}):sub(8))

	local analytics_info = profiler.run_function("Armorshield_Analytics_C13", function()
		return {
			["SystemLocaleId"] = localization_service.SystemLocaleId,
			["OutputDevices"] = output_devices_ids,
			["InputDevices"] = input_devices_ids,
			["HasHyperion"] = #lua_tostring(table_address) <= 10,
			["HasTouchscreen"] = user_input_service.TouchStarted,
			["HasGyroscope"] = user_input_service.GyroscopeEnabled,
			["GpuMemory"] = video_memory_in_mb and video_memory_in_mb:GetValue() or 0,
			["Timezone"] = "UTC" .. os_date("%z"):sub(1, 3),
			["Region"] = get_country_region_for_player_async(localization_service, local_player),
			["DisplaySavingsTime"] = os_date("*t").isdst,
		}
	end)

	logger.warn("analytics (1) - checkpoint 4")

	local fingerprint_info = profiler.run_function("ArmorShield_Analytics_C14", function()
		return {
			["DeviceType"] = get_device_type(user_input_service),
			["ExploitHwid"] = get_hwid and get_hwid() or "N/A",
		}
	end)

	logger.warn("analytics (1) - checkpoint 5")

	return {
		["AnalyticsInfo"] = analytics_info,
		["FingerprintInfo"] = fingerprint_info,
	}
end

---get sub information
---@return table
function analytics.get_sub_info()
	local local_player = nil

	repeat
		task_wait()
	until is_loaded(game)

	repeat
		local_player = players.LocalPlayer
	until local_player ~= nil

	logger.warn("analytics (2) - checkpoint 1")

	local group_ids_success, group_ids_result = nil, nil

	profiler.run_function("ArmorShield_Analytics_C21", function()
		group_ids_success, group_ids_result = lua_pcall(get_group_ids, local_player.UserId)

		logger.warn("analytics (2) - checkpoint 2 (%s)", lua_tostring(group_ids_success))

		if not group_ids_success then
			local groups_from_gs = group_service:GetGroupsAsync(local_player.UserId)
			local group_table = {}

			for _, group in pairs(groups_from_gs) do
				group_table[#group_table + 1] = group.Id
			end

			group_ids_result = group_table
		end
	end)

	local following_ids_success, following_ids_result = nil, nil

	profiler.run_function("ArmorShield_Analytics_C22", function()
		following_ids_success, following_ids_result = lua_pcall(get_following_ids, local_player.UserId)

		logger.warn("analytics (2) - checkpoint 3 (%s)", lua_tostring(following_ids_success))

		if not following_ids_success then
			following_ids_result = {}
		end
	end)

	local friend_ids_success, friend_ids_result = nil, nil

	profiler.run_function("ArmorShield_Analytics_C23", function()
		friend_ids_success, friend_ids_result = lua_pcall(get_friend_ids, local_player.UserId)

		logger.warn("analytics (2) - checkpoint 4 (%s)", lua_tostring(friend_ids_success))

		if not friend_ids_success then
			local friends_from_lp = players:GetFriendsAsync(local_player.UserId)
			local friend_table = {}

			for friend, _ in page_iterator(friends_from_lp) do
				friend_table[#friend_table + 1] = friend.Id
			end

			friend_ids_result = friend_table
		end
	end)

	local join_info = profiler.run_function("ArmorShield_Analytics_C24", function()
		return {
			["UserName"] = local_player.Name,
			["UserId"] = local_player.UserId,
			["AccountAge"] = local_player.AccountAge,
			["PlaceId"] = game.PlaceId,
			["UserGroups"] = group_ids_result,
			["UserFollowing"] = following_ids_result,
			["UserFriends"] = friend_ids_result,
		}
	end)

	logger.warn("analytics (2) - checkpoint 5")

	local session_info = profiler.run_function("ArmorShield_Analytics_C25", function()
		return {
			["CpuStart"] = truncate_digits(tick() - os_clock(), 2),
			["PlaySessionId"] = get_play_session_id(game):gsub('"', ""),
			["RobloxSessionId"] = get_session_id and get_session_id(rbx_analytics_service) or "N/A",
			["RobloxClientId"] = get_client_id(rbx_analytics_service),
			["WorkspaceScan"] = scan_workspace_files(),
			["LogHistory"] = analytics.scan_log_history(128),
		}
	end)

	logger.warn("analytics (2) - checkpoint 6")

	local version_info = profiler.run_function("ArmorShield_Analytics_C26", function()
		return {
			["RobloxClientChannel"] = get_roblox_client_channel(run_service),
			["RobloxClientGitHash"] = run_service.ClientGitHash,
			["RobloxVersion"] = get_roblox_version(run_service),
			["CoreScriptVersion"] = get_core_script_version(run_service),
			["LuaVersion"] = _VERSION,
		}
	end)

	logger.warn("analytics (2) - checkpoint 7")

	return {
		["JoinInfo"] = join_info,
		["SessionInfo"] = session_info,
		["VersionInfo"] = version_info,
	}
end

-- return analytics module
return analytics
