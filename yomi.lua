-- Yomi sandbox integration

local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"
local common = require "lua_scanners/common"
local lua_redis = require "lua_redis"

local N = 'yomi'

function Set (list)
  local set = {}
  for _, l in ipairs(list) do
    set[l] = true
  end
  return set
end

local function yomi_config(opts)

  local default_conf = {
    name = N,
    url = "",
    timeout = 5.0,
    log_virus = true,
    log_suspicious = true,
    log_unknown = false,
    log_clean = false,
    log_not_submitted = false,
    log_http_return_code = false,
    log_submission_state = false,
    log_attachment_mime_type = true,
    log_attachment_hash = true,
    error_retransmits = 3,
    hash_retransmits = 7,
    submission_info_retransmits = 7,
    retransmit_error_delay = 3,
    retransmit_hash_delay = 1,
    retransmit_submission_info_delay = 1,
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = true,
    virus_score = 0.7,
    suspicious_score = 0.4,
    mime_type_graylist = {}, -- mime types to scan, e.g. {"application/zip", "image/jpeg"}
    cache_expire = 7200, -- expire redis in 2h
    tmpdir = '/tmp',
    weight_correction = -1,
  }

  default_conf = lua_util.override_defaults(default_conf, opts)

  if not default_conf.prefix then
    default_conf.prefix = 'rs_' .. default_conf.name .. '_'
  end

  if not default_conf.log_prefix then
    if default_conf.name:lower() == default_conf.type:lower() then
      default_conf.log_prefix = default_conf.name
      default_conf.log_prefix = default_conf.name
    else
      default_conf.log_prefix = default_conf.name .. ' (' .. default_conf.type .. ')'
    end
  end

  default_conf.mime_type_graylist = Set(default_conf.mime_type_graylist)
  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function sleep(n)
  os.execute("sleep " .. tonumber(n))
end

local function log_message(info_level, message, task)
  if info_level then
    rspamd_logger.infox(task, message)
  else
    rspamd_logger.debugm(N, task, message)
  end
end

local function handle_yomi_result(result, task, rule, digest, file_name)
  local score = result['score']
  local malware_description = result['description']
  rspamd_logger.debugm(N, task, '%s: Yomi response score: %s, description: %s', rule.log_prefix, score, malware_description)

  if score then
    local symbol = ''
    local weight = 0
    local description = ''
    -- a file is a virus if the score is greater than virus_score
    if score > rule.virus_score then
      symbol = 'YOMI_VIRUS'
      weight = score * 10 + rule.weight_correction
      description = string.format('%s is dangerous: %s, score: %s', file_name, malware_description, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_virus, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    elseif score > rule.suspicious_score then
      symbol = 'YOMI_SUSPICIOUS'
      weight = score * 10 + rule.weight_correction
      description = string.format('%s is suspicious: %s, score: %s', file_name, malware_description, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_suspicious, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    elseif score < 0 then
      symbol = 'YOMI_UNKNOWN'
      weight = 0
      description = string.format('Unable to compute a score for %s: %s', file_name, malware_description)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_unknown, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    else
      symbol = 'YOMI_CLEAN'
      weight = score * 10 + rule.weight_correction
      description = string.format('%s is clean, score: %s', file_name, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_clean, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    end

    local cache_entry = { symbol, weight, description }
    rspamd_logger.debugm(N, task, '%s: saving to cache %s', rule.log_prefix, cache_entry)
    common.save_cache(task, digest, rule, cache_entry, 0.0)
  end
end

local function condition_check_and_continue(task, content, rule, digest, fn)
  local uncached = true
  local key = digest

  local function redis_av_cb(err, data)
    if data and type(data) == 'string' then
      -- Cached
      data = lua_util.str_split(data, '\t')
      local threat_string = lua_util.str_split(data[1], '\v')
      local score = data[2] or rule.default_score
      local symbol = threat_string[1]
      local weight = threat_string[2]
      local description = threat_string[3]
      rspamd_logger.debugm(N, task, '%s: cache hit: %s, %s, %s', rule.log_prefix, symbol, weight, description)
      task:insert_result(true, symbol, weight, description)
      uncached = false
    else
      if err then
        rspamd_logger.errx(task, '%s: got error checking cache: %s', rule.log_prefix, err)
      end
    end

    if uncached then
      fn()
    end
  end

  if rule.redis_params and not rule.no_cache then
    key = rule.prefix .. key

    if lua_redis.redis_make_request(task,
        rule.redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_av_cb, --callback
        'GET', -- command
        {key} -- arguments)
    ) then
      return true
    end
  end
  return false
end

local function should_skip_mime(detected_type, file_name, task, rule)
  if not rule.mime_type_graylist[detected_type] then
    log_message(rule.log_not_submitted,
        string.format('%s: attachment %s not submitted because has MIME type: %s', rule.log_prefix, file_name, detected_type), task)
    return true
  else
    return false
  end
end

local function get_mime_type(task, content, rule)
  local attachment_filename = string.format('%s/%s.tmp', rule.tmpdir, rspamd_util.random_hex(32))

  local attachment_fd = rspamd_util.create_file(attachment_filename)
  content:save_in_file(attachment_fd)

  local handle = io.popen(string.format('/usr/bin/file -b --mime-type \'%s\'', attachment_filename))
  local result = handle:read("*a")
  local mime_type = string.gsub(result, "\n", "")
  handle:close()

  task:get_mempool():add_destructor(function()
    rspamd_util.close_file(attachment_fd)
    os.remove(attachment_filename)
  end)

  return mime_type
end

local function get_attachment_info(task, content, rule)
  local attachment_info = {}
  local mime_parts = task:get_parts() or {}

  for _, mime_part in ipairs(mime_parts) do
    local string_content = tostring(content)
    local string_part_content = tostring(mime_part:get_content())

    if string_content == string_part_content then
      local file_name = mime_part:get_filename()

      if file_name ~= nil then
        local mime_type = get_mime_type(task, content, rule)
        attachment_info['file_name'] = file_name
        attachment_info['detected_type'] = mime_type
        attachment_info['size'] = mime_part:get_length()
      end
    end
  end
  return attachment_info
end

local function yomi_check(task, content, digest, rule)
  local hash_retransmits = rule.hash_retransmits
  local error_retransmits = rule.error_retransmits
  local submission_info_retransmits = rule.submission_info_retransmits

  local function yomi_check_uncached ()
    rspamd_logger.debugm(N, task, '%s: executing Yomi virus check', rule.log_prefix)

    -- skip check if sender is authenticated
    local sender = task:get_user()

    if not (sender == nil or sender == '') then
      task:insert_result(true, 'YOMI_SKIPPED', 0, 'Sender is authenticated')
      return
    end

    local attachment_info = get_attachment_info(task, content, rule)

    if attachment_info['file_name'] == nil then
      task:insert_result(true, 'YOMI_SKIPPED', 0, string.format('No file associated with part'))
      return
    end

    local file_name = attachment_info['file_name']
    local detected_type = attachment_info['detected_type']
    local file_size = attachment_info['size']

    if should_skip_mime(detected_type, file_name, task, rule) then
      task:insert_result(true, 'YOMI_SKIPPED', 0, string.format('%s has MIME type to skip: %s', file_name, detected_type))
      return
    end

    local system_id = rule.system_id
    local secret = rule.secret
    local auth = string.format("Basic %s", rspamd_util.encode_base64(system_id .. ":" .. secret))

    local hash = rspamd_cryptobox_hash.create_specific('sha256')
    hash:update(content)
    hash = hash:hex()

    local url = string.format('%s/hash/%s', rule.url, hash)
    rspamd_logger.debugm(N, task, '%s: sending request %s', rule.log_prefix, url)

    local request_data = {
      task = task,
      url = url,
      timeout = rule.timeout,
      headers = {
        ['Authorization'] = auth
      },
    }

    local function should_retransmit(http_code)
      if error_retransmits > 0 then
        error_retransmits = error_retransmits -1
        sleep(rule.retransmit_error_delay)
        return true
      else
        symbol = 'YOMI_UNKNOWN'
        weight = 0
        description = string.format('Maximum error retransmits exceeded for %s (HTTP %s)', file_name, http_code)
        task:insert_result(true, symbol, weight, description)
        log_message(rule.log_unknown, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
      end
      
      return false
    end

    local function should_retransmit_hash()
      if hash_retransmits > 0 then
        hash_retransmits = hash_retransmits -1
        sleep(rule.retransmit_hash_delay)
        return true
      else
        description = string.format('Maximum hash retransmits exceeded for %s', file_name)
        task:insert_result(true, 'YOMI_WAIT', 1, description)
        common.yield_result(task, rule, description, 0.0, 'fail')
      end
      
      return false
    end

    local function should_retransmit_submission_info()
      if submission_info_retransmits > 0 then
        submission_info_retransmits = submission_info_retransmits -1
        sleep(rule.retransmit_submission_info_delay)
        return true
      else
        description = string.format('Maximum sumbission info retransmits exceeded for %s', file_name)
        task:insert_result(true, 'YOMI_WAIT', 1, description)
        common.yield_result(task, rule, description, 0.0, 'fail')
      end

      return false
    end

    local function yomi_upload(task, content, hash, auth, rule)
      rspamd_logger.debugm(N, task, '%s: uploading to sandbox %s', rule.log_prefix, file_name)

      local request_data = {
        task = task,
        url = string.format('%s/submit', rule.url),
        timeout = rule.timeout,
        method = 'POST',
        mime_type='application/json',
        headers = {
          ['Authorization'] = auth
        },
        body = string.format('{"file": "%s", "hash": "%s", "name": "%s"}', rspamd_util.encode_base64(content), hash, attachment_info['file_name'])
      }
    
      local function upload_http_callback(http_err, code, body, headers)
        if http_err then
          rspamd_logger.errx(task, '%s: HTTP error: %s, body: %s, headers: %s', rule.log_prefix, http_err, body, headers)
          
          if should_retransmit(code) then
            yomi_upload(task, content, hash, auth, rule)
          end
        else
          log_message(rule.log_http_return_code, string.format('%s: upload returned %s (hash: %s)', rule.log_prefix, code, hash), task)
    
          if code == 202 then
            description = string.format('File uploaded: %s', file_name)
            task:insert_result(true, 'YOMI_WAIT', 1, description)
            common.yield_result(task, rule, description, 0.0, 'fail')
          elseif code == 401 or code == 403 then
            task:insert_result(true, 'YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
          elseif code == 200 then
            local parser = ucl.parser()
            local res,json_err = parser:parse_string(body)
    
            if res then
              local obj = parser:get_object()
              handle_yomi_result(obj, task, rule, digest, file_name)
            else
              -- not res
              rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)
              
              if should_retransmit(code) then
                yomi_upload(task, content, hash, auth, rule)
              end
            end
          else
            rspamd_logger.errx(task, '%s: invalid HTTP code: %s, body: %s, headers: %s', rule.log_prefix, code, body, headers)
            
            if should_retransmit(code) then
              yomi_upload(task, content, hash, auth, rule)
            end
          end
        end
      end
    
      request_data.callback = upload_http_callback
      http.request(request_data)
    end

    local function yomi_submission_info(task, submission_id)
      rspamd_logger.debugm(N, task, '%s: requesting submission info for id: %s', rule.log_prefix, submission_id)

      local request_data = {
        task = task,
        url = string.format('%s/submit/%s', rule.url, submission_id),
        timeout = rule.timeout,
        headers = {
          ['Authorization'] = auth
        },
      }

      local function submission_info_http_callback(http_err, code, body, headers)
        if http_err then
          rspamd_logger.errx(task, '%s: HTTP error: %s, body: %s, headers: %s', rule.log_prefix, http_err, body, headers)

          if should_retransmit(code) then
            yomi_submission_info(task, submission_id)
          end
        else
          log_message(rule.log_http_return_code, string.format('%s: submission info returned %s (hash: %s, submission_id: %s)', rule.log_prefix, code, hash, submission_id), task)

          if code == 401 or code == 403 then
            task:insert_result(true, 'YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
          elseif code == 202 then
            local parser = ucl.parser()
            local res, json_err = parser:parse_string(body)

            if res then
              local obj = parser:get_object()
              local state = obj['state']
              log_message(rule.log_submission_state, string.format('%s: submission_info_http_callback, state: %s', rule.log_prefix, state), task)

              if state == nil or state == '' or state == 'UNKNOWN' then
                -- submission info should be ready in a moment
                if should_retransmit_submission_info() then
                  yomi_submission_info(task, submission_id)
                end
              elseif state == 'WAITING' then
                -- analysis in progress
                description = string.format('Analysis in progress for %s', file_name)
                task:insert_result(true, 'YOMI_WAIT', 1, description)
                common.yield_result(task, rule, description, 0.0, 'fail')
              else
                rspamd_logger.errx(task, '%s: Unexpected submission state %s for %s', rule.log_prefix, state, file_name)

                if should_retransmit(code) then
                  yomi_submission_info(task, submission_id)
                end
              end
            else
              -- not res
              rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)

              if should_retransmit(code) then
                yomi_submission_info(task, submission_id)
              end
            end
          elseif code == 200 then
            local parser = ucl.parser()
            local res,json_err = parser:parse_string(body)

            if res then
              local obj = parser:get_object()
              handle_yomi_result(obj, task, rule, digest, file_name)
            else
              -- not res
              rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)

              if should_retransmit(code) then
                yomi_submission_info(task, submission_id)
              end
            end
          else
            rspamd_logger.errx(task, '%s: invalid HTTP code: %s, body: %s, headers: %s', rule.log_prefix, code, body, headers)

            if should_retransmit(code) then
              yomi_submission_info(task, submission_id)
            end
          end
        end
      end

      request_data.callback = submission_info_http_callback
      http.request(request_data)
    end

    local function hash_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, '%s: HTTP error: %s, body: %s, headers: %s', rule.log_prefix, http_err, body, headers)
        
        if should_retransmit(code) then
          yomi_check_uncached()
        end
      else
        log_message(rule.log_http_return_code, string.format('%s: hash returned %s (attachment: %s, MIME type: %s, hash: %s, size: %s)', rule.log_prefix, code, file_name, detected_type, hash, file_size), task)

        if code == 404 then
          rspamd_logger.debugm(N, task, '%s: hash %s not found', rule.log_prefix, hash)
          yomi_upload(task, content, hash, auth, rule)
        elseif code == 401 or code == 403 then
          task:insert_result(true, 'YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
        elseif code == 202 then
          local parser = ucl.parser()
          local res, json_err = parser:parse_string(body)

          if res then
            local obj = parser:get_object()
            local submission_id = obj['reference']

            if submission_id ~= nil and submission_id ~= '' then
              yomi_submission_info(task, submission_id)
            else
              -- submission_id not present
              local state = obj['state']

              if state and state == 'WAITING' then
                -- analysis in progress
                description = string.format('File analysis in progress for %s', file_name)
                task:insert_result(true, 'YOMI_WAIT', 1, description)
                common.yield_result(task, rule, description, 0.0, 'fail')
              else
                -- hash should be ready in a moment
                if should_retransmit_hash() then
                  yomi_check_uncached()
                end
              end
            end
          else
            -- not res
            rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)

            if should_retransmit(code) then
              yomi_check_uncached()
            end
          end
        elseif code == 200 then
          local parser = ucl.parser()
          local res,json_err = parser:parse_string(body)

          if res then
            local obj = parser:get_object()
            handle_yomi_result(obj, task, rule, digest, file_name)
          else
            -- not res
            rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)
            
            if should_retransmit(code) then
              yomi_check_uncached()
            end
          end
        else
          rspamd_logger.errx(task, '%s: invalid HTTP code: %s, body: %s, headers: %s', rule.log_prefix, code, body, headers)
          
          if should_retransmit(code) then
            yomi_check_uncached()
          end
        end
      end
    end

    request_data.callback = hash_http_callback
    http.request(request_data)
  end

  if condition_check_and_continue(task, content, rule, digest, yomi_check_uncached) then
    return
  else
    yomi_check_uncached()
  end
end

return {
  type = 'antivirus',
  description = 'Yomi sandbox integration',
  configure = yomi_config,
  check = yomi_check,
  name = N
}
