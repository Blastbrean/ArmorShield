-- logging module
local logger = {
	folder = "armorshield",
}

-- cached functions
local string_format, is_folder, is_file, make_folder, write_file, append_file, os_date, get_service, task_wait =
	string.format, isfolder, isfile, makefolder, writefile, appendfile, os.date, game.GetService, task.wait

-- services
local http_service = get_service(game, "HttpService")

-- cached service functions
local generate_guid = http_service.GenerateGUID

-- calculate initial logging file name - by date (unique per session)
local date_table = os_date("*t")
local logging_file_name = string_format(
	"armorshield_%i-%i-%i_%s.log",
	date_table.year,
	date_table.month,
	date_table.day,
	generate_guid(http_service, false)
)

---build prefix string from string
---@param str string
---@return string
function logger.build_prefix_string(str, ...)
	return string_format("[%s %s] [armorshield v1.0.0]: %s", os_date("%x"), os_date("%X"), str)
end

---add entry into log file with prefix
---@param entry string
function logger.add_entry(entry)
	if not is_folder(logger.folder) then
		make_folder(logger.folder)
	end

	local logging_path = string_format("%s/%s", logger.folder, logging_file_name)

	if not is_file(logging_path) then
		write_file(logging_path, entry)
	else
		append_file(logging_path, "\n" .. entry)
	end

	if ensure_logging then
		task_wait()
	end
end

---fatal log
---@param str string
function logger.fatal(str, ...)
	local message = string_format(logger.build_prefix_string(str), ...)
	logger.add_entry(string_format("[fatal] %s", message))
	error(message, math.huge)
end

---warn log
---@param str string
function logger.warn(str, ...)
	local message = string_format(logger.build_prefix_string(str), ...)
	logger.add_entry(string_format("[warn] %s", message))
	warn(message)
end

-- return logging module
return logger
