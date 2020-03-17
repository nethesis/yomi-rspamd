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
    error_retransmits = 3,
    hash_retransmits = 7,
    retransmit_error_delay = 3,
    retransmit_hash_delay = 1,
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    virus_score = 0.7,
    suspicious_score = 0.4,
    skip_mime_types = {}, -- file types to skip, e.g. { "pdf", "epub" }
    clean_weight = -0.5,
    suspicious_weight = 2,
    virus_weight = 5,
    cache_expire = 7200, -- expire redis in 2h
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

  default_conf.skip_mime_types = Set(default_conf.skip_mime_types)
  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function sleep(n)
  os.execute("sleep " .. tonumber(n))
end

local function should_retransmit(task, rule)
  if rule.error_retransmits > 0 then
    rule.error_retransmits = rule.error_retransmits -1
    sleep(rule.retransmit_error_delay)
    return true
  else
    task:insert_result(true, 'YOMI_FAIL', 1, 'Maximum error retransmits exceed')
  end
  
  return false
end

local function should_retransmit_hash(task, rule)
  if rule.hash_retransmits > 0 then
    rule.hash_retransmits = rule.hash_retransmits -1
    sleep(rule.retransmit_hash_delay)
    return true
  else
    task:insert_result(true, 'YOMI_FAIL', 1, 'Maximum hash retransmits exceed')
  end
  
  return false
end

local function log_message(info_level, message, task)
  if info_level then
    rspamd_logger.infox(task, message)
  else
    rspamd_logger.debugm(N, task, message)
  end
end

local function handle_yomi_result(result, task, rule, digest)
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
      weight = rule.virus_weight
      description = string.format('Virus found: %s, score: %s', malware_description, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_virus, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    elseif score > rule.suspicious_score then
      symbol = 'YOMI_SUSPICIOUS'
      weight = rule.suspicious_weight
      description = string.format('Suspicious file found: %s, score: %s', malware_description, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_suspicious, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    elseif score < 0 then
      symbol = 'YOMI_UNKNOWN'
      weight = 0
      description = "Unable to compute a score: " .. malware_description
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_unknown, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    else
      symbol = 'YOMI_CLEAN'
      weight = rule.clean_weight
      description = string.format('File is clean: %s, score: %s', malware_description, score)
      task:insert_result(true, symbol, weight, description)
      log_message(rule.log_clean, string.format('%s: %s (%s weight: %s)', rule.log_prefix, description, symbol, weight), task)
    end

    local cache_entry = { symbol, weight, description }
    rspamd_logger.debugm(N, task, '%s: saving to cache %s', rule.log_prefix, cache_entry)
    common.save_cache(task, digest, rule, cache_entry, 0.0)
  end
end

local function yomi_upload(task, content, hash, auth, rule)
  rspamd_logger.debugm(N, task, '%s: uploading to sandbox', rule.log_prefix)

  local request_data = {
    task = task,
    url = string.format('%s/submit', rule.url),
    timeout = rule.timeout,
    method = 'POST',
    mime_type='application/json',
    headers = {
      ['Authorization'] = auth
    },
    body = string.format('{"file": "%s", "hash": "%s"}', rspamd_util.encode_base64(content), hash)
  }

  local function upload_http_callback(http_err, code, body, headers)
    if http_err then
      rspamd_logger.errx(task, '%s: HTTP error: %s, body: %s, headers: %s', rule.log_prefix, http_err, body, headers)
      
      if should_retransmit(task, rule) then
        yomi_upload(task, content, hash, auth, rule)
      end
    else
      log_message(rule.log_http_return_code, string.format('%s: upload returned %s', rule.log_prefix, code), task)

      if code == 202 then
        task:insert_result(true, 'YOMI_WAIT', 1, 'File uploaded')
        common.yield_result(task, rule, 'File uploaded', 0.0, 'fail')
      elseif code == 401 or code == 403 then
        task:insert_result(true, 'YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
      elseif code == 200 then
        local parser = ucl.parser()
        local res,json_err = parser:parse_string(body)

        if res then
          local obj = parser:get_object()
          handle_yomi_result(obj, task, rule, digest)
        else
          -- not res
          rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)
          
          if should_retransmit(task, rule) then
            yomi_upload(task, content, hash, auth, rule)
          end
        end
      else
        rspamd_logger.errx(task, '%s: invalid HTTP code: %s, body: %s, headers: %s', rule.log_prefix, code, body, headers)
        
        if should_retransmit(task, rule) then
          yomi_upload(task, content, hash, auth, rule)
        end
      end
    end
  end

  request_data.callback = upload_http_callback
  http.request(request_data)
end

local function should_skip_mime(task, content, rule)
  local mime_parts = task:get_parts() or {}

  for _, mime_part in ipairs(mime_parts) do
    local string_content = tostring(content)
    local string_part_content = tostring(mime_part:get_content())

    if string_content == string_part_content then
      local detected_type = mime_part:get_detected_ext()

      if rule.skip_mime_types[detected_type] then
        log_message(rule.log_not_submitted, 
            string.format('%s: file not submitted because of its mime type: %s', rule.log_prefix, detected_type), task)
        return true
      end
    end
  end
  return false
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

local function yomi_check(task, content, digest, rule)
  local function yomi_check_uncached ()
    rspamd_logger.debugm(N, task, '%s: executing Yomi virus check', rule.log_prefix)

    if should_skip_mime(task, content, rule) then
      task:insert_result(true, 'YOMI_MIME_SKIPPED', 1, 'File not submitted because of its mime type')
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

    local function hash_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, '%s: HTTP error: %s, body: %s, headers: %s', rule.log_prefix, http_err, body, headers)
        
        if should_retransmit(task, rule) then
          yomi_check_uncached()
        end
      else
        log_message(rule.log_http_return_code, string.format('%s: hash returned %s', rule.log_prefix, code), task)

        if code == 404 then
          rspamd_logger.debugm(N, task, '%s: hash %s not found', rule.log_prefix, hash)
          yomi_upload(task, content, hash, auth, rule)
        elseif code == 401 or code == 403 then
          task:insert_result(true, 'YOMI_UNAUTHORIZED', 1, 'Unauthorized request returned ' .. code)
        elseif code == 202 then
          if should_retransmit_hash(task, rule) then
            yomi_check_uncached()
          end
        elseif code == 200 then
          local parser = ucl.parser()
          local res,json_err = parser:parse_string(body)

          if res then
            local obj = parser:get_object()
            handle_yomi_result(obj, task, rule, digest)
          else
            -- not res
            rspamd_logger.errx(task, '%s: invalid response', rule.log_prefix)
            
            if should_retransmit(task, rule) then
              yomi_check_uncached()
            end
          end
        else
          rspamd_logger.errx(task, '%s: invalid HTTP code: %s, body: %s, headers: %s', rule.log_prefix, code, body, headers)
          
          if should_retransmit(task, rule) then
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
